package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	"hash/fnv"

	docopt "github.com/docopt/docopt-go"
	imap "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	pwn "github.com/jrizza/haveibeenpwned"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {

	usage := `hackmeck
A small tool that collects all email addresses from your imaps server that
have received emails. All extracted emails, if described by the 
<doamins> argument, are checked by "https://haveibeenpwned.com". 

Used libraries are:
github.com/docopt/docopt-go
github.com/emersion/go-imap
github.com/jrizza/haveibeenpwned
github.com/sirupsen/logrus
golang.org/x/crypto/ssh/terminal

Usage:
  hackmeck -u <username>  [-p <password>] [options] [--ignore <ignore>...] <domains>...

Argument <domains>:
The argument <domains> includes the domain part of all email addresses 
to be tested against https://haveibeenpwned.com

If the domain "example.com" is specified, all email addresses ending 
with "@example.com" will be checked.
Thus test@example.com and spam@example.com will be checked but 
abuse@example.de will not be checked. 

Options:
  -h --help                show this help message and exit
  -v --version             show version and exit
  
  -a --all                 show also unverified breaches and pastes
 
  --host=<host>            imaps host [default: localhost]
  -p --port <port>         imaps port [default: 993]
  -u --user <user>         imap account username
  --password <password>    imap account password
 
  -i --ignore <ignore>     mailboxes that will no be checked for emil addresses
  -d --debug               show debug infos  
  -q --quiet               operate in quiet mode just show breaches`

	arguments, _ := docopt.ParseArgs(usage, nil, "0.0.1")

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	if arguments["--debug"].(bool) {
		log.SetLevel(log.DebugLevel)
	} else if arguments["--quiet"].(bool) {
		log.SetLevel(log.WarnLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.Debug("Commandline Argumenst:", arguments)

	log.Info("Connecting to server... ", arguments["--host"].(string)+":"+arguments["--port"].(string))

	imapClient, err := client.DialTLS(arguments["--host"].(string)+":"+arguments["--port"].(string), nil)
	if err != nil {
		log.Fatal("Error on connecting to server: ", err)
	}
	log.Debug("Connected")

	defer imapClient.Logout()

	log.Debug("Login: ", arguments["--user"].(string))

	password := arguments["--password"]
	if password == nil {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err == nil {
			password = string(bytePassword)
		} else {
			log.Fatal("Could not read password")
		}
	}

	if err := imapClient.Login(arguments["--user"].(string), password.(string)); err != nil {
		log.Fatal("Error on account login: ", arguments["--user"].(string), " --> ", err)
	}
	log.Info("Logged in")

	log.Debug("List mailboxes")

	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- imapClient.List("", "*", mailboxes)
	}()

	mboxes := make([]string, 0)
	for mbox := range mailboxes {
		mboxes = append(mboxes, mbox.Name)
	}

	mails := make(map[uint32]string)

	for _, mbox := range mboxes {

		log.Debug("Mailbox: " + mbox)

		if containsIgnoreCase(arguments["--ignore"].([]string), mbox) {
			log.Debug("Ignore mailbox: ", mbox)
			continue
		}

		mboxStatus, err := imapClient.Select(mbox, true)
		if err != nil {
			log.Fatal("Error on selecting mailbox: ", mbox, err)
		}

		from := uint32(1)
		to := mboxStatus.Messages

		if to == 0 {
			continue
		}

		log.Infof("Grep emailaddresses from % 5d messages in %s", to, mbox)

		seqset := new(imap.SeqSet)
		seqset.AddRange(from, to)

		messages := make(chan *imap.Message, 10)
		done = make(chan error, 1)
		go func() {
			done <- imapClient.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
		}()

		h := fnv.New32a()

		for msg := range messages {
			for _, addr := range msg.Envelope.To {
				if addr.MailboxName != "" && addr.HostName != "" && containsIgnoreCase(arguments["<domains>"].([]string), addr.HostName) {
					eMail := strings.ToLower(addr.MailboxName + "@" + addr.HostName)
					h.Reset()
					h.Write([]byte(eMail))
					mails[h.Sum32()] = eMail
				}
			}
			for _, addr := range msg.Envelope.Cc {
				if addr.MailboxName != "" && addr.HostName != "" && containsIgnoreCase(arguments["<domains>"].([]string), addr.HostName) {
					eMail := strings.ToLower(addr.MailboxName + "@" + addr.HostName)
					h.Reset()
					h.Write([]byte(eMail))
					mails[h.Sum32()] = eMail
				}
			}
		}
	}

	for _, v := range mails {
		log.Info("Check breaches for: ", v)
		data, err := pwn.BreachedAccount(v, "", false, arguments["--all"].(bool))
		if data != nil && err == nil {
			for _, breach := range data {
				log.Warn("Pwned account: ", v, " by: ", breach.Name, breach.Title, breach.Domain, breach.DataClasses)
			}

		}
		if err != nil {
			log.Error("Error on check breaches for account: ", v, err)
			continue
		}
		if arguments["--all"].(bool) {
			time.Sleep(2 * time.Second)
			log.Info("Check pastes for:   ", v)
			pastes, err := pwn.PasteAccount(v)
			if pastes != nil && err == nil {
				for _, paste := range pastes {
					log.Warn("Paste account: ", v, " by: ", paste.Source, paste.Title)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}

	if err := <-done; err != nil {
		log.Fatal(err)
	}
	log.Info("Done!")
}

func containsIgnoreCase(collection []string, value string) bool {
	for _, v := range collection {
		if strings.ToLower(v) == strings.ToLower(value) {
			return true
		}
	}
	return false
}
