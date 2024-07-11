---
title: Recon-ng 🦥
tags:
  - TryHackMe
  - Theory
---
[Recon-ng](https://github.com/lanmaster53/recon-ng) is a framework that helps automate the OSINT work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related online API. In this task, we will demonstrate using Recon-ng in the terminal.

From a penetration testing and red team point of view, Recon-ng can be used to find various bits and pieces of information that can aid in an operation or OSINT task. All the data collected is automatically saved in the database related to your workspace. For instance, you might discover host addresses to later port-scan or collect contact email addresses for phishing attacks.

You can start Recon-ng by running the command `recon-ng`. Starting Recon-ng will give you a prompt like `[recon-ng][default] >`. At this stage, you need to select the installed module you want to use. However, if this is the first time you're running `recon-ng`, you will need to install the module(s) you need.

In this task, we will follow the following workflow:

1. Create a workspace for your project
2. Insert the starting information into the database
3. Search the marketplace for a module and learn about it before installing
4. List the installed modules and load one
5. Run the loaded module

### Creating a Workspace

Run `workspaces create WORKSPACE_NAME` to create a new workspace for your investigation. For example, `workspaces create thmredteam` will create a workspace named `thmredteam`.

`recon-ng -w WORKSPACE_NAME` starts recon-ng with the specific workspace.

### Seeding the Database

In reconnaissance, you are starting with one piece of information and transforming it into new pieces of information. For instance, you might start your research with a company name and use that to discover the domain name(s), contacts and profiles. Then you would use the new information you obtained to transform it further and learn more about your target.

Let’s consider the case where we know the target's domain name, `thmredteam.com`, and we would like to feed it into the Recon-ng database related to the active workspace. If we want to check the names of the tables in our database, we can run `db schema`.

We want to insert the domain name `thmredteam.com` into the domains table. We can do this using the command `db insert domains`.

````shell
           
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > db insert domains
domain (TEXT): thmredteam.com
notes (TEXT): 
[*] 1 rows affected.
[recon-ng][thmredteam] > marketplace search
````

### Recon-ng Marketplace

We have a domain name, so a logical next step would be to search for a module that transforms domains into other types of information. Assuming we are starting from a fresh installation of Recon-ng, we will search for suitable modules from the marketplace.

Before you install modules using the marketplace, these are some useful commands related to marketplace usage:

- `marketplace search KEYWORD` to search for available modules with _keyword_.
- `marketplace info MODULE` to provide information about the module in question.
- `marketplace install MODULE` to install the specified module into Recon-ng.
- `marketplace remove MODULE` to uninstall the specified module.

The modules are grouped under multiple categories, such as discovery, import, recon and reporting. Moreover, recon is also divided into many subcategories depending on the transform type. Run `marketplace search` to get a list of all available modules.

In the terminal below, we search for modules containing `domains-`.

````shell
           
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > marketplace search domains-
[*] Searching module index for 'domains-'...

  +---------------------------------------------------------------------------------------------------+
  |                        Path                        | Version |     Status    |  Updated   | D | K |
  +---------------------------------------------------------------------------------------------------+
  | recon/domains-companies/censys_companies           | 2.0     | not installed | 2021-05-10 | * | * |
  | recon/domains-companies/pen                        | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-companies/whoxy_whois                | 1.1     | not installed | 2020-06-24 |   | * |
  | recon/domains-contacts/hunter_io                   | 1.3     | not installed | 2020-04-14 |   | * |
  | recon/domains-contacts/metacrawler                 | 1.1     | not installed | 2019-06-24 | * |   |
  | recon/domains-contacts/pen                         | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-contacts/pgp_search                  | 1.4     | not installed | 2019-10-16 |   |   |
  | recon/domains-contacts/whois_pocs                  | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-contacts/wikileaker                  | 1.0     | not installed | 2020-04-08 |   |   |
  | recon/domains-credentials/pwnedlist/account_creds  | 1.0     | not installed | 2019-06-24 | * | * |
  | recon/domains-credentials/pwnedlist/api_usage      | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-credentials/pwnedlist/domain_creds   | 1.0     | not installed | 2019-06-24 | * | * |
  | recon/domains-credentials/pwnedlist/domain_ispwned | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-credentials/pwnedlist/leak_lookup    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-credentials/pwnedlist/leaks_dump     | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-domains/brute_suffix                 | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/domains-hosts/binaryedge                     | 1.2     | not installed | 2020-06-18 |   | * |
  | recon/domains-hosts/bing_domain_api                | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-hosts/bing_domain_web                | 1.1     | not installed | 2019-07-04 |   |   |
  | recon/domains-hosts/brute_hosts                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/builtwith                      | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/censys_domain                  | 2.0     | not installed | 2021-05-10 | * | * |
  | recon/domains-hosts/certificate_transparency       | 1.2     | not installed | 2019-09-16 |   |   |
  | recon/domains-hosts/google_site_web                | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/hackertarget                   | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/domains-hosts/mx_spf_ip                      | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/netcraft                       | 1.1     | not installed | 2020-02-05 |   |   |
  | recon/domains-hosts/shodan_hostname                | 1.1     | not installed | 2020-07-01 | * | * |
  | recon/domains-hosts/spyse_subdomains               | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/ssl_san                        | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatcrowd                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatminer                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-vulnerabilities/ghdb                 | 1.1     | not installed | 2019-06-26 |   |   |
  | recon/domains-vulnerabilities/xssed                | 1.1     | not installed | 2020-10-18 |   |   |
  +---------------------------------------------------------------------------------------------------+

  D = Has dependencies. See info for details.
  K = Requires keys. See info for details.

[recon-ng][thmredteam] >
````

We notice many subcategories under `recon`, such as `domains-companies`, `domains-contacts`, and `domains-hosts`. This naming tells us what kind of new information we will get from that transformation. For instance, `domains-hosts` means that the module will find hosts related to the provided domain.

Some modules, like `whoxy_whois`, require a key, as we can tell from the `*` under the `K` column. This requirement indicates that this module is not usable unless we have a key to use the related service.

Other modules have dependencies, indicated by a `*` under the `D` column. Dependencies show that third-party Python libraries might be necessary to use the related module.

Let’s say that you are interested in `recon/domains-hosts/google_site_web`. To learn more about any particular module, you can use the command `marketplace info MODULE`; this is an essential command that explains what the module does. For example, `marketplace info google_site_web` provides the following description: “Harvests hosts from Google.com by using the ‘site’ search operator. Updates the ‘hosts’ table with the results.” In other words, this module will use the Google search engine and the “site” operator.

We can install the module we want with the command `marketplace install MODULE`, for example, `marketplace install google_site_web`.

### Working with Installed Modules

We can work with modules using:

- `modules search` to get a list of all the installed modules
- `modules load MODULE` to load a specific module to memory

Let’s load the module that we installed earlier from the marketplace, `modules load viewdns_reverse_whois`. To `run` it, we need to set the required options.

- `options list` to list the options that we can set for the loaded module.
- `options set <option> <value>` to set the value of the option.

In a previous step, we have installed the module `google_site_web`, so let’s load it using `load google_site_web` and run it with `run`. We have already added the domain `thmredteam.com` to the database, so when the module is run, it will read that value from the database, get new kinds of information, and add them to the database in turn. The commands and the results are shown in the terminal output below.

````shell
           
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > modules load google_site_web
[recon-ng][thmredteam][google_site_web] > run

--------------
THMREDTEAM.COM
--------------
[*] Searching Google for: site:thmredteam.com
[*] Country: None
[*] Host: cafe.thmredteam.com
[*] Ip_Address: None
[*] Latitude: None
[*] Longitude: None
[*] Notes: None
[*] Region: None
[*] --------------------------------------------------
[*] Country: None
[*] Host: clinic.thmredteam.com
[*] Ip_Address: None
[*] Latitude: None
[*] Longitude: None
[*] Notes: None
[*] Region: None
[*] --------------------------------------------------
[...]
[*] 2 total (2 new) hosts found.
[recon-ng][thmredteam][google_site_web] >
````

This module has queried Google and discovered two hosts, `cafe.thmredteam.com` and `clinic.thmredteam.com`. It is possible that by the time you run these steps, new hosts will also appear.

### Keys

Some modules cannot be used without a key for the respective service API. `K` indicates that you need to provide the relevant service key to use the module in question.

- `keys list` lists the keys
- `keys add KEY_NAME KEY_VALUE` adds a key
- `keys remove KEY_NAME` removes a key

Once you have the set of modules installed, you can proceed to load and run them.

- `modules load MODULE` loads an installed module
- `CTRL + C` unloads the module.
- `info` to review the loaded module’s info.
- `options list` lists available options for the chosen module.
- `options set NAME VALUE`
- `run` to execute the loaded module.

*NOTE: to see actual data inputted do `$ input`*
*NOTE: we can make queries like this: `$ db query select * from domains`*


