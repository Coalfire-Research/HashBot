'''
hash.py - Willie module that calls hashcat
Love, DanMcInerney
'''
# Willie installation
# https://flexion.org/posts/2014-08-installing-willie-irc-bot-on-debian.html

import io
import os
import re
import time
import glob
import pipes
import string
import random
import signal
import smtplib
import paramiko
import subprocess
import multiprocessing
from willie.module import commands, example

sessions = {} 
# Get all rulefiles (and only files, no dirs) from the rules directory
rulepath = '/opt/oclHashcat-1.36/rules/'
all_rules = [f for f in os.listdir(rulepath) if os.path.isfile(os.path.join(rulepath, f))]

@commands('help')
def help(bot, trigger):
    '''
    Print out the rules and hash types
    '''
    # Examples
    bot.msg(trigger.nick, 'Usage: ".hash [hashmode] [ruleset] [hash] [hash] [hash] ... [email]"')
    bot.msg(trigger.nick, 'Type ".rules" to see a list of rules available')
    bot.msg(trigger.nick, 'Type ".sessions" to see a list of active sessions')
    bot.msg(trigger.nick, 'Type ".kill <sessionname>" to kill an active session; enter one session at a time')
    bot.msg(trigger.nick, 'Output files are dumped to 10.0.0.240:/home/hashbot/ in format <sessionname>-cracked-<6 char ID>.txt')

@commands('rules')
def rules(bot, trigger):
    '''
    Hardcoded list of rules, might make the bot SSH to the rules
    dir and list them that way at some point but for now this is
    easier and the rules don't change hardly ever
    '''
    bot.say('Rules: (takes a moment)')
    bot.say('%s' % ' | '.join(all_rules))

@commands('kill')
def kill(bot, trigger):
    '''
    Kill a session
    Cleanup occurs automatically
    '''
    global sessions
    kill_session = trigger.group(2)
    if kill_session:
        kill_session = kill_session.strip()
        if kill_session in sessions:
            bot.say('Killing session: %s' % kill_session)
            os.killpg(sessions[kill_session].pid, signal.SIGTERM)
            return

    bot.say('No session by that name found. Please enter a single session to kill, .kill <sessionname>, \
or type .sessions to see all sessions')

@commands('sessions')
def sessions_printer(bot, trigger):
    '''
    Print all sessions
    '''
    if len(sessions) == 0:
        bot.say('No current sessions initiatied by HashBot')
    else:
        sessions_list = [k for k in sessions]
        bot.say('Current sessions: %s' % ' '.join(sessions_list))

@commands('hash')
def hash(bot, trigger):
    '''
    Function that's called when user types .hash
    '''
    sanitize = re.compile('[\W_]+')
    # trigger = u'.hash arg1 arg2...'
    # trigger.group(1) = u'hash'
    # trigger.group(2) = u'arg1 arg2...'
    if not trigger.group(2):
        wrong_cmd(bot)
        return

    args = trigger.group(2).split()
    if len(args) > 1:

        # Sanitize the nick
        nick = str(trigger.nick)
        sani_nick = sanitize.sub('', nick)

        mode, rule, hashes, email = get_options(bot, args, nick)
        if mode and rule and hashes:
            # Handle hashcat sessions
            sessionname = session_handling(sani_nick)
            filename = '/tmp/%s-hashes.txt' % sessionname

            # Download hash file (hashes is a list]
            if 'http://' in hashes[0]:
                # Sanitize the URL for shell chars
                cmd = ['/usr/bin/wget', '-O', filename, pipes.quote(hashes[0])]
                subprocess.call(cmd)

            # If no URL, proceed with textually input hashes
            else:
                write_hashes_to_file(bot, hashes, nick, filename)

            run_cmds(bot, nick, sessionname, mode, rule, email)
    else:
        wrong_cmd(bot)

def session_handling(sani_nick):
    '''
    Keep track of the sessions
    '''
    # Prevent dupe sessions
    counter = 1
    sessionname = sani_nick
    while sessionname in sessions:
        sessionname = sani_nick + str(counter)
        counter += 1

    return sessionname

def get_options(bot, args, nick):
    '''
    Grab the args the user gives
    '''
    email = None
    rule = None
    hashes = args[1:]
    mode = args[0]
    common_hashcat_codes = {'ntlm':'1000', 'netntlmv2':'5600', 'ntlmv2':'5600', 'netntlmv1':'5500',
                            'sha1':'100', 'md5':'0', 'sha512':'1800', 'kerberos':'7500'}
    if mode in common_hashcat_codes:
        mode = common_hashcat_codes[mode]

    # Pull out the rule and email from the args
    for x in hashes:
        # Check if a rule was used, right now only supports one rule
        if x in all_rules:
            rule = x
        # Check for an email address, the only hash that may have an @ in it is Lastpass
        # so we gotta make sure the string with @ doesn't also have a : which Lastpass does
        if '@' in x and ':' not in x:
            email = x

    # Remove the email address and rule from the list of hashes if they exist
    if email:
        hashes.remove(email)
    if rule:
        hashes.remove(rule)
    else:
        rule = 'best64.rule'
        bot.msg(nick,'Defaulting to best64.rule. Type .rules to see a list of available rulesets.')

    if len(hashes) == 0:
        bot.say('No hashes entered. Please enter in form: .hash [hashtype] [ruleset] [hash] [hash] ... [email]')
        return None, None, None

    return mode, rule, hashes, email

def create_identifier():
    identifier = ''
    for x in xrange(0,6):
        identifier += random.choice(string.letters)
    return identifier

def run_cmds(bot, nick, sessionname, mode, rule, email):
    '''
    Handle interaction with crackerbox
    '''
    global sessions
    identifier = create_identifier()

    #Create hashcat cmd
    cmd = create_cmd(bot, nick, sessionname, mode, rule, identifier)
    split_cmd = cmd.split()

    # Continuously poll cracked pw file while waiting for hashcat to finish
    cracked = find_cracked_pw(bot, nick, sessionname, mode, identifier, split_cmd)

    cleanup(bot, nick, sessionname, len(cracked), email, identifier)

def create_cmd(bot, nick, sessionname, mode, rule, identifier):
    '''Create hashcat cmd'''
    wordlists = ' '.join(glob.glob('/opt/wordlists/*'))
    cmd = '/opt/oclHashcat-1.36/oclHashcat64.bin \
--session %s -m %s -o /home/hashbot/%s-cracked-%s.txt /tmp/%s-hashes.txt %s \
-r /opt/oclHashcat-1.36/rules/%s'\
% (sessionname, mode, sessionname, identifier, sessionname, wordlists, rule)
    print_cmd = '/opt/oclHashcat-1.36/oclHashcat64.bin \
--session %s -m %s -o /home/hashbot/%s-cracked-%s.txt /tmp/%s-hashes.txt /opt/wordlists/* \
-r /opt/oclHashcat-1.36/rules/%s'\
% (sessionname, mode, sessionname, identifier, sessionname, rule)

    bot.say('Hashcat session name: %s' % sessionname)
    bot.msg(nick, 'Cmd: %s' % print_cmd)

    return cmd

def write_hashes_to_file(bot, hashes, nick, filename):
    '''
    Write to /tmp/sessionname-hashes.txt
    '''
    with open(filename, 'a+') as f:
        for h in hashes:
            h = clean_hash(bot, h, nick)
            if h != None:
                f.write(h+'\n')

def clean_hash(bot, h, nick):
    '''
    Sanitize and confirm hash doesn't have blank hex/unicode chars
    '''
    # Sometimes copy pasta causes blank characters at the end or beginning
    try:
        h.decode('utf8')
    except UnicodeEncodeError:
        bot.msg(nick, 'Unicode encode error with hash: %s' % repr(h))
        bot.msg(nick, 'If you copy and pasted it, try just deleting and retyping \
the first and last characters')
        return

    return h

def find_cracked_pw(bot, nick, sessionname, mode, identifier, split_cmd):
    '''
    While the hashcat cmd is running, constantly check sessionname-output.txt
    for cracked hashes
    '''
    cracked = []

    output_file = '%s-output-%s.txt' % (sessionname, identifier)

    with open(output_file, 'w') as f:
        # Run hashcat
        hashcat_cmd = subprocess.Popen(split_cmd, stdout=f, stderr=f, preexec_fn=os.setsid)
        sessions[sessionname] = hashcat_cmd

        while hashcat_cmd.poll() is None:
            cracked += read_cracked_pws(mode, bot, cracked, sessionname, nick, '%s.pot' % sessionname)
            time.sleep(1)

    # If it ends in error
    with open(output_file, 'r') as out:
        output = out.read()
        err = print_errors(bot, output)

    # Check one more time for cracked pws
    cracked += read_cracked_pws(mode, bot, cracked, sessionname, nick, '%s.pot' % sessionname)

    print cracked   
    return cracked

def print_errors(bot, output):
    '''Check and print errors'''
    lines = output.splitlines()
    for l in lines:
        if 'WARNING:' in l or 'ERROR:' in l:
            bot.say(l)
            return True

def read_cracked_pws(mode, bot, cracked, sessionname, nick, pw_file):
    '''Read from hashcats cracked file'''
    new_cracked = []

    if os.path.isfile(pw_file):
        with open(pw_file) as f:
            for l in f.readlines():
                # Prevent the cracked message from being too long for ntlmv2
                if mode in ['5600','ntlmv2', 'netntlmv2']:
                    l = l.split(':')
                    try:
                        # IRC has char limits that hashes sometimes exceed
                        l = l[0]+':'+l[2]+':'+l[-1]
                    except IndexError:
                        continue
                if l not in cracked:
                    bot.msg(nick, 'Cracked! %s' % l)
                    new_cracked.append(l)

    return new_cracked

def send_email(email, sessionname, cracked, cracked_file):
    '''
    If user gave an email in the args, send an email when a hash is cracked
    '''
    # If the session is killed with ".kill" cmd, then cracked_file may not exist
    try:
        cracked_hashes = open(cracked_file).read()
    except IOError:
        cracked_hashes = "Session killed with \".kill\" command and no hashes were cracked."

    from_addr = 'HashbotCF@gmail.com'
    password = open('/home/hashbot/.willie/modules/mail-password.txt').read()
    msg = "\r\n".join(["From: %s" % from_addr,
                       "To: %s" % email,
                       "Subject: Hashcat session \"%s\" completed" % sessionname,
                       "",
                       "Finished hashcat session \"%s\", cracked %s hash(es)\n" % (sessionname, str(cracked)),
                       cracked_hashes])

    try:
        # The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(from_addr,password)
        server.sendmail(from_addr, email, msg)
        server.quit()
    except Exception as e:
        print '[-] Emailed to %s failed: %s' % (email, str(e))

def cleanup(bot, nick, sessionname, cracked, email, identifier):
    '''
    Cleanup the left over files, save the hashes
    '''
    global sessions

    cracked_file = '/home/hashbot/%s-cracked-%s.txt' % (sessionname, identifier)
    cracked_pws = '/home/hashbot/%s-output.txt' % sessionname
    log_file = '/home/hashbot/%s-log-%s.txt' % (sessionname, identifier)
    #err_file = '/home/hashbot/%s-errors-%s.txt' % (sessionname, identifier)

    # Move the cracked hashes and log files to ID'd filenames
    if os.path.isfile(cracked_pws):
        subprocess.call(['mv', cracked_pws, cracked_file])
    if os.path.isfile(log_file):
        subprocess.call(['mv', '%s.log' % sessionname, log_file])
   
    # Cleanup files
    subprocess.call(['rm', '-rf', '/home/hashbot/%s.pot' % sessionname, 
                     '/tmp/%s-hashes.txt' % sessionname, 
                     '/home/hashbot/%s.induct' % sessionname, 
                     '/home/hashbot/%s.restore' % sessionname, 
                     '/home/hashbot/%s.outfiles' % sessionname])

    del sessions[sessionname]
    bot.reply('completed session %s and cracked %s hash(es)' % (sessionname, str(cracked)))
    bot.msg(nick,'Hashcat finished, %d hash(es) stored on 10.0.0.240 at %s and %s'\
% (cracked, cracked_file, log_file))

    # Send an email if it was given
    if email:
        send_email(email, sessionname, cracked, cracked_file)

def wrong_cmd(bot):
    bot.say('Please enter hashes in the following form:')
    bot.say('.hash [hashtype] [ruleset] [hash] [hash] [hash] ...')
    bot.say('.hash ntlmv2 best64.rule 9D7E463A630AD...')
    bot.say('Use ".help" to see available rulesets and hashtypes')
