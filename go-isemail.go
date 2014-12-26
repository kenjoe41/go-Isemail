package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"reflect"
	"sort"
)

var (
	user string
	domain string
	mxhosts []string
	localhost string
	exclude_addresses []string
	debug = 0
	email_domains_white_list []string
	hostDomains []string
)

//loads any CSV file passed to it using a buffer
//Returns a slice of individual CSV elements and Error
func loadCSVfile(file *os.File) ([]string, error){
	const NBUF = 512
	var buf [NBUF]byte
	result []string
	for {
		switch nr, err := f.Read(buf[:]); true {
	
		case nr < 0:
			return nil, errors.New(err.Error())
	
		case nr == 0: // EOF; not considered an error//return nil, io.EOF
			return
	
		case nr > 0://ok, read the data
			result = append(result, buf[0:nr])
		}
	}
	return result, nil
}

//Split Email Address into username and Domain.
//If it has no domain part, domain is "localhost"
//else Error
func splitEmailAddress(address string) error{
	email_parts := strings.Split(address)
	v := reflect.ValueOf(email_parts)//get underling value to test its type

	if (v.Kind() == reflect.Slice) {//if underlying value is slice, then email has domain part
		user = strings.ToLower(email_parts[0])
		domain = strings.ToLower(email_parts[1])
		return nil
	}else if (v.Kind() == reflect.String){//Has no domain part, assume its testing local email server:"localhost"
		user = strings.ToLower(address)
		domain = strings.ToLower("localhost")
		return nil
	}else{
		return errors.New("Couldn't split address: Wrong format")
	}
}

//Non-exported function
//True if email address matches regexp
//False otherwise.
func validateEmailAddress(address string) bool{
	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$") //regex for email structure;
	
	return re.MatchString(address)
}

//Verifies Email address domain for MX DNS records
//Return number of MX host if Email Address is valid
//Retuns 0 if invalid Email address
func validateEmailHost(address string) int {
	if(!validateEmailAddress(address)){}
		return 0
	}

	err := splitEmailAddress(address)
	checkError(err)

	mxhosts, err := net.LookupMX(domain)
	checkError(err)

	return len(mxhosts)
}

//Checks for error, logs the error and panics
func checkError(err error) {
	if err != nil {		
		log.Fatalf("%s\n", err)
	}
}

//SMTP raw command sender
func putMsg(conn net.Conn, msg string){
	fmt.Printf("C %s\n", msg)
	io.WriteString(conn, msg)//send our message
}

//SMTP return message reader from socket
func socketRead(conn net.Conn, code uint){
	// read the response from the webserver
	for read {
		count, err = con.Read(data)
		read = (err == nil)
		if debug{
			fmt.Printf("S %s\n"string(data[0:count]))
		}
	}
}

//searches for given IP in given struct
func searchIP(src []string, ip string) bool{
	if net.ParseIP(ip) = nil{
		if debug{
			log.Printf("Wrong IP structure: %s", ip)
		}
		return false
	}
	indx := sort.SearchString(src, ip)
	if indx < len(src) && src[indx]==ip{
		return true
	}else{
		return false
	}
}



//Exported Functions
func ValidateEmailBox(address string) int{
	if(!validateEmailHost(address)){
		return 0
	}

	if((localhost!="") && ((localhost=os.Getenv("SERVER_NAME")!="") && ((localhost=os.Getenv("HOST")!=""){
		localhost = "localhost"//setting global variable to localhost
	}
	if((localuser!="") && ((localuser=os.Getenv("USERNAME")!="") && ((localuser=os.Getenv("USER")!=""){
		localhost = "root"//setting global variable to localuser
	}
	IPre := regexp.MustCompile(`/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/`)//ip regexp.
	var ip string
	for mxhost := range mxhosts{
		if IPre.MatchString(mxhost){
			ip = mxhost
		}else{
			if debug{			
				log.Printf("Resolving host name: %s\n", mxhost)
			}
			if ips, err := net.LookupIP(mxhost); err != nil{
				if debug{
					log.Printf("Couldn't resolve host %s. Error: %s\n",err)
				}
				continue
			}
		}
		for ip_indx := range ips{
			if(len(exclude_addresses)){
				var validIPs []string
				for ex_addr := exclude_addresses{
					if ex_ip, err := net.LookupIP(ex_addr); err!=nil{
						if debug{
							log.Printf("Couldn't resolve host %s. Error: %s\n",err)
						}
						continue
					}
					if searchIP(ex_ip, ip_indx){
						if debug{
							log.Printf("Host address of %s is in the exclude addresses\n", ip_indx)
						}
						continue
					}else{
						validIPs = append(validIPs, ip_indx)
					}
				}
				ip = validIPs[0] //we only need one
			}else{
				ip = ip_indx
				break
			}
		if debug{
			fmt.Printf("Connecting to host address %s...", ip)
		}
				
		//create a socket to talk to smtp server
		var (
			host = ip
			port = 25
			remote = host + ":" + port
			data = make([]uint8, 4096)
			read = true
			count = 0
			sender = localuser + "@" + localhost
			reciever = address
		)

		client, err := smtp.Dial(remote)
		chechError(err)
		fmt.Println("Connected.")//220

		socketRead(client)//HElO: 250
		fmt.Fprintf(senderMsg, "MAIL FROM: <%s>", sender)
		putMsg(client, senderMsg)
		socketRead(client)//250
		fmt.Fprintf(rcptMsg, "RCPT TO: <%s>", reciever)
		putMsg(client, rcptMsg)
		socketRead(client)//250
		putMsg(client, "DATA")
		socketRead(client)//354
		//TODO: verify returned code and better error checking to finally say that box is Valid
				

		/*// Set the sender and recipienst.
		 if err := client.Mail(sender); err = nil{
			fmt.Println()
		}
		 client.Rcpt(reciever)
		 // Send the email body.
		 wc, err := client.Data()
		 if err != nil {			
			log.Fatalln(err)
		 }
		 defer wc.Close()

		}*/
	}
}

//Validates the Email address given
func ValidateAddress(address) (string, valid int){
	valid = -1
	err := splitEmailAddress(address)
	chechError(err)

	if len(email_domains_white_list_file){
		email_domains_white_list, err = loadCSVfile(email_domains_white_list_file)
		checkError(err)

		for emailDomain := range email_domain_white_list{
			emailDomain = strings.ToLower(emailDomain[0])
			if emailDomain == domain{//Given Email Address' domain
				if debug{
					log.Printf("Email Address' domain %s is valid because it is in white list.", domain)
				}
			valid = 0
			return ""
			}
		}
	}

	if len(invalid_email_users_file){
		invalid_email_users, err = loadCSVfile(invalid_email_users_file)
		checkError(err)

		for emailUser := range invalid_email_users{
			emailUser = strings.ToLower(emailUser[0])
			if emailUser == user || strings.Contain(user, emailUser){
				if debug{
					log.Printf("Email Address' user %s is invalid because it is in invalid users' list", user)
				}
			valid = 0
			validation_status_code = EMAIL_VALIDATION_STATUS_BANNED_WORDS_IN_USER
			return ""
			}
		}
	}

	if len(invalid_email_domains_file){
		invalid_email_domains, err = loadCSVfile(invalid_email_domains_file)
		checkError(err)

		check string
		for invalidEmailDomain := range invalid_email_domains{
			match := strings.ToLower(invalidEmailDomain[0])
			if len(invalidEmailDomain) != 3 || len(invalidEmailDomain) != 4{
				if debug{
					log.Printf("Domain entry for %s is incorrectly defined", invalidEmailDomain)
				}
				check = "part"
			}else{
				check = invalidEmailDomain[2]
			}

			switch check{
				case "":
					if !(match == domain) || strings.Contain(domain, strings.Join(".", match)){
						valid = false
						break 2
					}
					break
				case "part":
					if strings.Contain(domain, match){
						if debug{
						log.Printf("Email Domain %s is invalid because it contains %s", domain, match)
						}
						valid = false
						break 2
					}
					break
			}
			if !valid{
				switch invalidEmailDomain[1]{
					case "fake":
						if debug{
							log.Printf("%s is a fake Email Domain", domain)
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_FAKE_DOMAIN
						break
					case "typo":
						if debug{
							log.Printf("%s email domain has a typo", domain)
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_TYPO_IN_DOMAIN
						break
					case "disposable":
						if debug{
							log.Printf("%s is a disposable email domain", domain)
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_DISPOSABLE_ADDRESS
						break
					case "temporary":
						if debug{
							log.Printf("%s is a temporary Email Domain", domain)	
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_TEMPORARY_DOMAIN
						break
					case "spam trap":
						if debug{
							log.Printf("%s is a spam trap domain", domain)
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_SPAM_TRAP_ADDRESS
						break
					case "":
						if debug{
							log.Printf("%s ends in %s", domain, match)
						}
						validation_status_code = EMAIL_VALIDATION_STATUS_BANNED_DOMAIN
						break
				}
			}
		}
		return ""
	}
	if len(invalid_email_servers_file){
		if mxhosts, err = net.LookupMX(domain); err != nil{
			if debug{			
				log.Printf("email domain %s may be valid because it was not possible to get its MX servers", domain)
			}
		}else{
			invalid_email_servers, err = loadCSVfile(invalid_email_servers_file)
			checkError(err)
		}

		for i := 0; i<len(mxhosts); i++{
			mxhost := mxhosts[i]
			mxhostIPs, err := net.LookupIP(mxhost)
			checkError(err)
			
			for j :=0; j<len(mxhostIPs); j++{
				if !searchIP(hostDomains, mxhostIPs[j]){//mxhostsIPs not in hostDomains
					
				}
			}
		}
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: isemail Email-Address : \nE.g. $isemail kenjoe41@mailinator.com\n")
		os.Exit(1)
	}

	email := os.Args[1]

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$") //regex for email structure;
	if re.MatchString(email) {
		fmt.Print("Email-Address structure is valid...\n")
	} else {
		log.Fatal("[-]Wrong Email-Address structure!\n")

	}

	//split email into uname and host
	email_parts := strings.Split(email, "@") //returns an array
	host := email_parts[1]
	if _, err := net.LookupHost(host); err != nil {
		fmt.Printf("[-]But DNS lookup failed for host: %s \n", host)
		log.Fatal(err)
	} else {
		fmt.Print("[+]And Dns lookup was successful!\n")
	}
	fmt.Print("[\u263A]Email Address %v is valid.\n", email)
}
