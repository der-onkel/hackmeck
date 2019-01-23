# hackmeck

A small tool that collects all email addresses from your imaps server that
have received emails. All extracted emails, if described by the
_&lt;doamins&gt;_ argument, are checked by <https://haveibeenpwned.com>.

## Usage


    hackmeck -u <username>  [-p <password>] [options] [--ignore <ignore>...] <domains>...

### Argument &lt;domains&gt;

The argument _&lt;domains&gt;_ includes the domain part of all email addresses
to be tested against <https://haveibeenpwned.com>

If the domain "example.com" is specified, all email addresses ending
with "@example.com" will be checked.
Thus test@example.com and spam@example.com will be checked but
abuse@example.de will not be checked.

### Options

    -h --help               show this help message and exit  
    -v --version            show version and exit
  
    -a --all                show also unverified breaches and pastes  
  
    --host <host>           imaps host [default: localhost]  
    -p --port <port>        imaps port [default: 993]  
    -u --user <username>    imap account username  
    --password >password>   imap account password  
  
    -i --ignore >ignore>    mailboxes that will no be checked for emil addresses  
    -d --debug              show debug infos  
    -q --quiet              operate in quiet mode just show breaches  

### Used libraries are

* github.com/docopt/docopt-go
* github.com/emersion/go-imap
* github.com/jrizza/haveibeenpwned
* github.com/sirupsen/logrus
* golang.org/x/crypto/ssh/terminal