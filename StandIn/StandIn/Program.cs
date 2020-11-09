using System;
using CommandLine;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;

namespace StandIn
{
    class Program
    {
        public static void returnObject(String sObject, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = sObject;

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("[!] Object not found..");
                    return;
                } else if (oObject.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get object details
                foreach (SearchResult sr in oObject)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    // retrieve object properties
                    ResultPropertyCollection omProps = sr.Properties;
                    Console.WriteLine("\n[?] Iterating object properties\n");
                    foreach (String sKey in omProps.PropertyNames)
                    {
                        Console.WriteLine("[+] " + sKey);
                        if (sKey == "objectsid")
                        {
                            Console.WriteLine("    |_ " + new SecurityIdentifier((Byte[])omProps[sKey][0], 0).ToString());
                        }
                        else if (sKey == "objectguid")
                        {
                            Console.WriteLine("    |_ " + new Guid((Byte[])omProps[sKey][0]).ToString());
                        }
                        else if (
                            sKey == "pwdlastset" ||
                            sKey == "lastlogon" ||
                            sKey == "lastlogontimestamp" ||
                            sKey == "accountexpires" ||
                            sKey == "lastLogoff" ||
                            sKey == "badpasswordtime")
                        {
                            long kerbTime = (long)omProps[sKey][0];
                            if (kerbTime == long.MaxValue)
                            {
                                Console.WriteLine("    |_ 0x7FFFFFFFFFFFFFFF");
                            } else if (kerbTime == 0)
                            {
                                Console.WriteLine("    |_ 0x0");
                            } else
                            {
                                Console.WriteLine("    |_ " + DateTime.FromFileTimeUtc((long)omProps[sKey][0]) + " UTC");
                            }
                        }
                        else if (sKey == "msds-allowedtoactonbehalfofotheridentity")
                        {
                            RawSecurityDescriptor rsd = new RawSecurityDescriptor((Byte[])omProps[sKey][0], 0);
                            foreach (CommonAce ace in rsd.DiscretionaryAcl)
                            {
                                Console.WriteLine("    |_ BinLen           : " + ace.BinaryLength);
                                Console.WriteLine("    |_ AceQualifier     : " + ace.AceQualifier.ToString());
                                Console.WriteLine("    |_ IsCallback       : " + ace.IsCallback);
                                Console.WriteLine("    |_ OpaqueLength     : " + ace.OpaqueLength);
                                Console.WriteLine("    |_ AccessMask       : " + ace.AccessMask);
                                Console.WriteLine("    |_ SID              : " + ace.SecurityIdentifier.ToString());
                                Console.WriteLine("    |_ AceType          : " + ace.AceType.ToString());
                                Console.WriteLine("    |_ AceFlags         : " + ace.AceFlags);
                                Console.WriteLine("    |_ IsInherited      : " + ace.IsInherited);
                                Console.WriteLine("    |_ InheritanceFlags : " + ace.InheritanceFlags);
                                Console.WriteLine("    |_ PropagationFlags : " + ace.PropagationFlags);
                                Console.WriteLine("    |_ AuditFlags       : " + ace.AceFlags);
                            }
                        }
                        else if (sKey == "useraccountcontrol")
                        {
                            try
                            {
                                Console.WriteLine("    |_ " + (hStandIn.USER_ACCOUNT_CONTROL)omProps[sKey][0]);
                            } catch
                            {
                                Console.WriteLine("    |_ " + omProps[sKey][0]);
                            }
                        }
                        else if (sKey == "samaccounttype")
                        {
                            try
                            {
                                Console.WriteLine("    |_ " + (hStandIn.SAM_ACCOUNT_TYPE)omProps[sKey][0]);
                            }
                            catch
                            {
                                Console.WriteLine("    |_ " + omProps[sKey][0]);
                            }
                        }
                        else if (sKey == "msds-supportedencryptiontypes")
                        {
                            try
                            {
                                Console.WriteLine("    |_ " + (hStandIn.SUPPORTED_ETYPE)omProps[sKey][0]);
                            }
                            catch
                            {
                                Console.WriteLine("    |_ " + omProps[sKey][0]);
                            }
                        }
                        else
                        {
                            foreach (Object oColl in omProps[sKey])
                            {
                                if (oColl is byte[])
                                {
                                    Console.WriteLine("    |_ " + BitConverter.ToString((Byte[])oColl).Replace("-", " "));
                                }
                                else
                                {
                                    Console.WriteLine("    |_ " + oColl);
                                }
                            }
                        }
                    }
                }

            } catch
            {
                Console.WriteLine("[!] Failed to enumerate object properties..");
                return;
            }
        }

        public static void setAllowedToActOnBehalfOfOtherIdentity(String sMachineName, String sObjectSID, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass, true);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(samaccountname={0}$)", sMachineName);

            // Act
            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Host not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    // Check if msDS-AllowedToActOnBehalfOfOtherIdentity exists bail if yes, set if not
                    if (sr.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
                    {
                        Console.WriteLine("[!] This host already has a msDS-AllowedToActOnBehalfOfOtherIdentity property..");
                        return;
                    } else
                    {
                        RawSecurityDescriptor rs = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sObjectSID + ")");
                        Byte[] bDescriptor = new byte[rs.BinaryLength];
                        rs.GetBinaryForm(bDescriptor, 0);
                        mde.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Add(bDescriptor);
                        mde.CommitChanges();
                        Console.WriteLine("[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to set host msDS-AllowedToActOnBehalfOfOtherIdentity property..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine(ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine(ex.Message);
                }
                return;
            }
        }

        public static void removeAllowedToActOnBehalfOfOtherIdentity(String sMachineName, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass, true);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(samaccountname={0}$)", sMachineName);

            // Act
            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Host not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    // Check if msDS-AllowedToActOnBehalfOfOtherIdentity remove if yes, bail if not
                    if (sr.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
                    {
                        mde.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Clear();
                        mde.CommitChanges();
                        Console.WriteLine("[+] msDS-AllowedToActOnBehalfOfOtherIdentity property removed..");
                    }
                    else
                    {
                        Console.WriteLine("[!] This host does not have a msDS-AllowedToActOnBehalfOfOtherIdentity property..");
                        return;
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to remove host msDS-AllowedToActOnBehalfOfOtherIdentity property..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine(ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine(ex.Message);
                }
                return;
            }
        }

        public static void LDAPMakeMachineAccount(String sMachineName, String sDomain = "", String sUser = "", String sPass = "")
        {
            // We can't set the machine unicodePwd using DirectoryEntry so
            // we use LdapConnection but it's is less friendly..
            try
            {
                Domain oDom = Domain.GetComputerDomain();
                String sPDC = oDom.PdcRoleOwner.Name;

                String sDomName = oDom.Name;
                String sDistName = "CN=" + sMachineName + ",CN=Computers";
                foreach (String sPart in sDomName.ToLower().Split(new Char[] { '.' }))
                {
                    sDistName += ",DC=" + sPart;
                }
                Console.WriteLine("\n[?] Using DC    : " + sPDC);
                Console.WriteLine("    |_ Domain   : " + sDomName);
                Console.WriteLine("    |_ DN       : " + sDistName);

                // Are we supplying creds?
                NetworkCredential credObj = null;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    credObj = new NetworkCredential(sUser, sPass, sDomain);
                }

                // Create connection object
                LdapDirectoryIdentifier oConId = new LdapDirectoryIdentifier(sPDC, 389);
                LdapConnection oConObject = null;
                if (credObj != null)
                {
                    oConObject = new LdapConnection(oConId, credObj);
                } else
                {
                    oConObject = new LdapConnection(oConId);
                }

                // Initiate an LDAP bind
                oConObject.SessionOptions.Sealing = true; // Encrypt and sign our
                oConObject.SessionOptions.Signing = true; // session traffic
                oConObject.Bind();

                // Create machine object
                AddRequest oLDAPReq = new AddRequest();
                oLDAPReq.DistinguishedName = sDistName;
                oLDAPReq.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                oLDAPReq.Attributes.Add(new DirectoryAttribute("SamAccountName", sMachineName + "$"));
                oLDAPReq.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                oLDAPReq.Attributes.Add(new DirectoryAttribute("DnsHostName", sMachineName + "." + sDomName));
                oLDAPReq.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", new String[] { "HOST/" + sMachineName + "." + sDomName, "RestrictedKrbHost/" + sMachineName + "." + sDomName, "HOST/" + sMachineName, "RestrictedKrbHost/" + sMachineName }));

                // Set machine password
                String sMachinePass = hStandIn.genAccountPass();
                Console.WriteLine("    |_ Password : " + sMachinePass);
                oLDAPReq.Attributes.Add(new DirectoryAttribute("unicodePwd", System.Text.Encoding.Unicode.GetBytes('"' + sMachinePass + '"')));

                // Send request
                try
                {
                    oConObject.SendRequest(oLDAPReq);
                    Console.WriteLine("\n[+] Machine account added to AD..");
                } catch (Exception ex)
                {
                    Console.WriteLine("\n[!] Failed to add machine account to AD..");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine("    |_ " + ex.InnerException.Message);
                    }
                    else
                    {
                        Console.WriteLine("    |_ " + ex.Message);
                    }
                }
            } catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain properties..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void disableMachineAccount(String sMachineName, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(samaccountname={0}$)", sMachineName);

            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Host not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    // retrieve object properties
                    ResultPropertyCollection omProps = sr.Properties;

                    // Check and disable machine account
                    Int32 iAcctCon = (Int32)omProps["userAccountControl"][0];
                    Boolean isAccountEnabled = !Convert.ToBoolean(iAcctCon & 0x0002);
                    if (isAccountEnabled)
                    {
                        Console.WriteLine("\n[+] Machine account currently enabled");
                        try
                        {
                            mde.Properties["userAccountControl"].Value = iAcctCon | 0x2;
                            mde.CommitChanges();
                            Console.WriteLine("    |_ Account disabled..");
                        } catch
                        {
                            Console.WriteLine("\n[!] Failed to disable machine account..");
                        }
                    } else
                    {
                        Console.WriteLine("\n[+] Machine account already disabled");
                        Console.WriteLine("    |_ Exiting..");
                    }
                }
            } catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain object..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void deleteMachineAccount(String sMachineName, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(samaccountname={0}$)", sMachineName);

            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Host not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);
                    try
                    {
                        sr.GetDirectoryEntry().DeleteTree();
                        Console.WriteLine("\n[+] Machine account deleted from AD");
                    }
                    catch
                    {
                        Console.WriteLine("\n[!] Failed to delete machine account..");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain object..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void getObjectAccessPermissions(String sObject, String sNTAccount = "", String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = sObject;

            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Object not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);
                    try
                    {
                        Console.WriteLine("\n[+] Object properties");
                        Console.WriteLine("    |_ Owner : " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());
                        Console.WriteLine("    |_ Group : " + mde.ObjectSecurity.GetGroup(typeof(NTAccount)).ToString());

                        AuthorizationRuleCollection arc = mde.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));
                        Console.WriteLine("\n[+] Object access rules");
                        foreach (ActiveDirectoryAccessRule ar in arc)
                        {
                            if (ar.IdentityReference.Value == sNTAccount || String.IsNullOrEmpty(sNTAccount))
                            {
                                Console.WriteLine("\n[+] Identity --> " + ar.IdentityReference.Value);
                                Console.WriteLine("    |_ Type       : " + ar.AccessControlType.ToString());
                                Console.WriteLine("    |_ Permission : " + ar.ActiveDirectoryRights.ToString());
                                if (ar.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000")
                                {
                                    Console.WriteLine("    |_ Object     : ANY");
                                }
                                else
                                {
                                    String sSchemaFriendlyName = hStandIn.schemaGUIDToFriendlyName(ar.ObjectType, sDomain, sUser, sPass);
                                    if (String.IsNullOrEmpty(sSchemaFriendlyName))
                                    {
                                        String sRightsFriendlyName = hStandIn.rightsGUIDToFriendlyName(ar.ObjectType, sDomain, sUser, sPass);
                                        if (String.IsNullOrEmpty(sRightsFriendlyName))
                                        {
                                            Console.WriteLine("    |_ Object     : " + ar.ObjectType.ToString());
                                        }
                                        else
                                        {
                                            Console.WriteLine("    |_ Object     : " + sRightsFriendlyName);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("    |_ Object     : " + sSchemaFriendlyName);
                                    }
                                }
                            }
                        }
                    } catch
                    {
                        Console.WriteLine("[!] Failed to resolve object access properties..");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain object..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void grantObjectAccessPermissions(String sObject, hStandIn.AccessRequest oAccess, String sGUID, String sNTAccount, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = sObject;

            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Object not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);
                    try
                    {
                        Console.WriteLine("\n[+] Object properties");
                        Console.WriteLine("    |_ Owner : " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());
                        Console.WriteLine("    |_ Group : " + mde.ObjectSecurity.GetGroup(typeof(NTAccount)).ToString());
                        Console.WriteLine("\n[+] Set object access rules");
                        IdentityReference ir = new NTAccount(sNTAccount);

                        if (oAccess == hStandIn.AccessRequest.genericall)
                        {
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.GenericAll, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        } else if (oAccess == hStandIn.AccessRequest.genericwrite)
                        {
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.GenericWrite, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        } else if (oAccess == hStandIn.AccessRequest.resetpassword)
                        {
                            Guid rightGuid = new Guid("00299570-246d-11d0-a768-00aa006e0529"); // User-Force-Change-Password
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        } else if (oAccess == hStandIn.AccessRequest.writemembers)
                        {
                            Guid rightGuid = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"); // Member
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        } else if (oAccess == hStandIn.AccessRequest.dcsync)
                        {
                            Guid rightGuid = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"); // DS-Replication-Get-Change
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);

                            rightGuid = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"); // DS-Replication-Get-Changes-All
                            ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);

                            rightGuid = new Guid("89e95b76-444d-4c62-991a-0facbeda640c"); // DS-Replication-Get-Changes-In-Filtered-Set
                            ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        } else if (!String.IsNullOrEmpty(sGUID))
                        {
                            Guid rightGuid = new Guid(sGUID); // Custom rights guid
                            ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                            mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                            mde.ObjectSecurity.AddAccessRule(ar);
                        }

                        mde.CommitChanges();
                        if (Enum.GetName(typeof(hStandIn.AccessRequest), oAccess) != "none")
                        {
                            Console.WriteLine("    |_ Success, added " + Enum.GetName(typeof(hStandIn.AccessRequest), oAccess) + " privileges to object for " + sNTAccount);
                        } else
                        {
                            Console.WriteLine("    |_ Success, added GUID rights privilege to object for " + sNTAccount);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to set object access properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain object..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void setAccountPassword(String sObject, String sNewPass, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = sObject;

            try
            {
                // Search
                SearchResultCollection oMachine = ds.FindAll();

                // Did we get 1 result back?
                if (oMachine.Count == 0)
                {
                    Console.WriteLine("[!] Object not found..");
                    return;
                }
                else if (oMachine.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Get machine details
                foreach (SearchResult sr in oMachine)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);
                    try
                    {
                        Console.WriteLine("\n[+] Object properties");
                        Console.WriteLine("    |_ Owner : " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());
                        Console.WriteLine("    |_ Group : " + mde.ObjectSecurity.GetGroup(typeof(NTAccount)).ToString());

                        Console.WriteLine("\n[+] Setting account password");
                        mde.Invoke("SetPassword", new object[] { sNewPass });
                        mde.CommitChanges();
                        Console.WriteLine("    |_ Success, password set for object");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to set object password..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to resolve domain object..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void addUserToGroup(String sGroup, String sAddUser, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                PrincipalContext pc = null;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    String sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    pc = new PrincipalContext(ContextType.Domain, sDomain, sUser, sPass);
                }
                else
                {
                    pc = new PrincipalContext(ContextType.Domain);
                }

                Console.WriteLine("\n[?] Using DC : " + pc.ConnectedServer);

                GroupPrincipal oGroup = GroupPrincipal.FindByIdentity(pc, sGroup);
                Console.WriteLine("[?] Group    : " + oGroup.Name);
                Console.WriteLine("    GUID     : " + oGroup.Guid.ToString());
                if (oGroup == null)
                {
                    Console.WriteLine("[!] Failed to resolve group..");
                } else
                {
                    Console.WriteLine("\n[+] Adding user to group");
                    oGroup.Members.Add(pc, IdentityType.SamAccountName, sAddUser);
                    oGroup.Save();
                    Console.WriteLine("    |_ Success");
                }
            } catch (Exception ex)
            {
                Console.WriteLine("[!] Failed add user to group..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void getGroupMembership(String sGroup, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                PrincipalContext pc = null;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    String sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    pc = new PrincipalContext(ContextType.Domain, sDomain, sUser, sPass);
                }
                else
                {
                    pc = new PrincipalContext(ContextType.Domain);
                }

                Console.WriteLine("\n[?] Using DC : " + pc.ConnectedServer);

                GroupPrincipal oGroup = GroupPrincipal.FindByIdentity(pc, sGroup);
                Console.WriteLine("[?] Group    : " + oGroup.Name);
                Console.WriteLine("    GUID     : " + oGroup.Guid.ToString());
                if (oGroup == null)
                {
                    Console.WriteLine("[!] Failed to resolve group..");
                }
                else
                {
                    Console.WriteLine("\n[+] Members");
                    PrincipalCollection gms = oGroup.Members;

                    foreach (Principal m in gms)
                    {
                        DirectoryEntry mde = (DirectoryEntry)m.GetUnderlyingObject();
                        Console.WriteLine("\n[?] Path           : " + mde.Path);
                        Console.WriteLine("    samAccountName : " + m.SamAccountName);
                        if ((Int32)mde.Properties["samaccounttype"].Value == 268435456)
                        {
                            Console.WriteLine("    Type           : Group");
                        } else if ((Int32)mde.Properties["samaccounttype"].Value == 805306368)
                        {
                            Console.WriteLine("    Type           : User");
                        } else
                        {
                            Console.WriteLine("    Type           : " + mde.Properties["samaccounttype"].Value);
                        }
                        Console.WriteLine("    SID            : " + m.Sid);
                        
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed add user to group..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void getSPNAccounts(String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("[?] Found " + oObject.Count + " kerberostable users..");

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName         : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName      : " + omProps["distinguishedName"][0].ToString());
                        Console.WriteLine("    ServicePrincipalName   : " + omProps["servicePrincipalName"][0].ToString());
                        long lastPwdSet = 0;
                        try
                        {
                            lastPwdSet = (long)omProps["pwdlastset"][0];
                        } catch { }
                        if (lastPwdSet == long.MaxValue)
                        {
                            Console.WriteLine("    PwdLastSet             : 0x7FFFFFFFFFFFFFFF");
                        }
                        else if (lastPwdSet == 0)
                        {
                            Console.WriteLine("    PwdLastSet             : 0x0");
                        }
                        else
                        {
                            Console.WriteLine("    PwdLastSet             : " + DateTime.FromFileTimeUtc((long)omProps["pwdlastset"][0]) + " UTC");
                        }
                        try
                        {
                            long logonTimestamp = (long)omProps["lastlogon"][0];
                            if (logonTimestamp == long.MaxValue)
                            {
                                Console.WriteLine("    lastlogon              : 0x7FFFFFFFFFFFFFFF");
                            }
                            else if (logonTimestamp == 0)
                            {
                                Console.WriteLine("    lastlogon              : 0x0");
                            }
                            else
                            {
                                Console.WriteLine("    lastlogon              : " + DateTime.FromFileTimeUtc((long)omProps["lastlogon"][0]) + " UTC");
                            }
                        } catch
                        {
                            try
                            {
                                long logonTimestamp = (long)omProps["lastlogontimestamp"][0];
                                if (logonTimestamp == long.MaxValue)
                                {
                                    Console.WriteLine("    lastlogontimestamp     : 0x7FFFFFFFFFFFFFFF");
                                }
                                else if (logonTimestamp == 0)
                                {
                                    Console.WriteLine("    lastlogontimestamp     : 0x0");
                                }
                                else
                                {
                                    Console.WriteLine("    lastlogontimestamp     : " + DateTime.FromFileTimeUtc((long)omProps["lastlogontimestamp"][0]) + " UTC");
                                }
                            } catch
                            {
                                Console.WriteLine("    lastlogontimestamp     : N/A");
                            }
                        }
                        hStandIn.SUPPORTED_ETYPE etypes = (hStandIn.SUPPORTED_ETYPE)0;
                        if (omProps.Contains("msDS-SupportedEncryptionTypes")) {
                            etypes = (hStandIn.SUPPORTED_ETYPE)omProps["msDS-SupportedEncryptionTypes"][0];
                        }
                        Console.WriteLine("    Supported ETypes       : " + etypes);
                    } catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to enumerate DirectoryEntry properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate SPN accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void getDelegationAccounts(String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Unconstrained delegation filter
            ds.Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("\n[?] Found " + oObject.Count + " object(s) with unconstrained delegation..");

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());
                        Console.WriteLine("    userAccountControl       : " + (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0]);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to enumerate DirectoryEntry properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }

            // Constrained delegation filter
            ds.Filter = "(&(msDS-AllowedToDelegateTo=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("\n[?] Found " + oObject.Count + " object(s) with constrained delegation..");

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());
                        UInt32 iDelegateCount = 0;
                        foreach (Object oColl in omProps["msds-allowedtodelegateto"])
                        {
                            if (iDelegateCount == 0)
                            {
                                Console.WriteLine("    msDS-AllowedToDelegateTo : " + oColl);
                            }
                            else
                            {
                                Console.WriteLine("                               " + oColl);
                            }
                            iDelegateCount += 1;
                        }
                        if (((Int32)mde.Properties["userAccountControl"].Value & (Int32)hStandIn.USER_ACCOUNT_CONTROL.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) != 0)
                        {
                            Console.WriteLine("    Protocol Transition      : True");
                        }
                        else
                        {
                            Console.WriteLine("    Protocol Transition      : False");
                        }
                        Console.WriteLine("    userAccountControl       : " + (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0]);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to enumerate DirectoryEntry properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }

            // Resource-Based Constrained delegation filter
            ds.Filter = "(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum  
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("\n[?] Found " + oObject.Count + " object(s) with resource-based constrained delegation..");

                // For each account that has rbcd configured on it pointing to other objects
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());


                        String sFilter = "(&(|";
                        RawSecurityDescriptor rsd = new RawSecurityDescriptor((byte[])omProps["msDS-AllowedToActOnBehalfOfOtherIdentity"][0], 0);
                        // Get the ACE for each entry in the object's DACL, each of which points to an object that has inbound RBCD privileges.
                        foreach (CommonAce ace in rsd.DiscretionaryAcl)
                        {
                            sFilter = sFilter + "(objectSid=" + ace.SecurityIdentifier.ToString() + ")";
                        }
                        sFilter = sFilter + ")(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

                        ds.Filter = sFilter;
                        SearchResultCollection delegationObjs = ds.FindAll();

                        UInt32 iDelegateCount = 0;
                        // Parse the results of the search query to get for each object that has inbound RBCD privileges on the current object.
                        foreach (SearchResult delegationObj in delegationObjs)
                        {
                            ResultPropertyCollection srProps = delegationObj.Properties;
                            if (iDelegateCount == 0)
                            {
                                if (srProps.Contains("grouptype"))
                                {
                                    Console.WriteLine("    Inbound Delegation       : " + srProps["samAccountName"][0].ToString() + " [GROUP]");
                                } else
                                {
                                    Console.WriteLine("    Inbound Delegation       : " + srProps["samAccountName"][0].ToString());
                                }
                            }
                            else
                            {
                                if (srProps.Contains("grouptype"))
                                {
                                    Console.WriteLine("                               " + srProps["samAccountName"][0].ToString() + " [GROUP]");
                                }
                                else
                                {
                                    Console.WriteLine("                               " + srProps["samAccountName"][0].ToString());
                                }
                            }
                            iDelegateCount += 1;
                        }
                        Console.WriteLine("    userAccountControl       : " + (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0]);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to enumerate DirectoryEntry properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void getASREPAccounts(String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // ASREP filter
            ds.Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("\n[?] Found " + oObject.Count + " object(s) that do not require Kerberos preauthentication..");

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());
                        UInt32 iDelegateCount = 0;
                        foreach (Object oColl in omProps["msds-allowedtodelegateto"])
                        {
                            if (iDelegateCount == 0)
                            {
                                Console.WriteLine("    msDS-AllowedToDelegateTo : " + oColl);
                            }
                            else
                            {
                                Console.WriteLine("                               " + oColl);
                            }
                            iDelegateCount += 1;
                        }
                        Console.WriteLine("    userAccountControl       : " + (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0]);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to enumerate DirectoryEntry properties..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void setASREP(String sObject, Boolean sRemove = false, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = sObject;

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("[!] Object not found..");
                    return;
                }
                else if (oObject.Count > 1)
                {
                    Console.WriteLine("[!] Invalid search, multiple results returned..");
                    return;
                }

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        Console.WriteLine("[?] Object   : " + mde.Name);
                        Console.WriteLine("    Path     : " + mde.Path);

                        ResultPropertyCollection omProps = sr.Properties;

                        hStandIn.USER_ACCOUNT_CONTROL accountProps;
                        try
                        {
                            accountProps = (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0];
                        } catch
                        {
                            Console.WriteLine("[!] Failed to get userAccountControl property..");
                            return;
                        }

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());
                        Console.WriteLine("    userAccountControl       : " + (hStandIn.USER_ACCOUNT_CONTROL)omProps["useraccountcontrol"][0]);

                        // Check if the current flags have DONT_REQUIRE_PREAUTH
                        Boolean hasASREP = (Boolean)((accountProps & hStandIn.USER_ACCOUNT_CONTROL.DONT_REQUIRE_PREAUTH) != 0);
                        if (hasASREP && !sRemove)
                        {
                            Console.WriteLine("\n[!] userAccountControl flags already contains DONT_REQUIRE_PREAUTH..");
                            return;
                        } else if (hasASREP && sRemove)
                        {
                            mde.Properties["useraccountcontrol"].Value = accountProps & ~hStandIn.USER_ACCOUNT_CONTROL.DONT_REQUIRE_PREAUTH;
                        } else if (!hasASREP && !sRemove)
                        {
                            mde.Properties["useraccountcontrol"].Value = accountProps | hStandIn.USER_ACCOUNT_CONTROL.DONT_REQUIRE_PREAUTH;
                        } else
                        {
                            Console.WriteLine("\n[!] userAccountControl flags do not contain DONT_REQUIRE_PREAUTH..");
                            return;
                        }

                        Console.WriteLine("\n[+] Updating userAccountControl..");
                        mde.CommitChanges();
                        Console.WriteLine("    |_ Success");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to update userAccountControl flags..");
                        if (ex.InnerException != null)
                        {
                            Console.WriteLine("    |_ " + ex.InnerException.Message);
                        }
                        else
                        {
                            Console.WriteLine("    |_ " + ex.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate accounts..");
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    |_ " + ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("    |_ " + ex.Message);
                }
            }
        }

        public static void GetADDomainControllers()
        {
            try
            {
                Domain oDom = Domain.GetComputerDomain();
                String sPDC = oDom.PdcRoleOwner.Name;
                String sDomName = oDom.Name;
                Console.WriteLine("\n[?] Using DC    : " + sPDC);
                Console.WriteLine("    |_ Domain   : " + sDomName);

                DomainControllerCollection aDCCol = oDom.DomainControllers;
                foreach (DomainController dc in aDCCol)
                {
                    Console.WriteLine("\n[*] Host                  : " + dc.Name);
                    Console.WriteLine("    Domain                : " + dc.Domain);
                    Console.WriteLine("    Forest                : " + dc.Forest);
                    Console.WriteLine("    SiteName              : " + dc.SiteName);
                    Console.WriteLine("    IP                    : " + dc.IPAddress);
                    Console.WriteLine("    OSVersion             : " + dc.OSVersion);
                    Console.WriteLine("    Local System Time UTC : " + dc.CurrentTime.ToUniversalTime().ToString("dddd, dd MMMM yyyy HH:mm:ss"));
                    try
                    {
                        UInt32 iRoleCount = 0;
                        foreach (ActiveDirectoryRole role in dc.Roles)
                        {
                            if (iRoleCount == 0)
                            {
                                Console.WriteLine("    Role                  : " + role.ToString());
                            } else
                            {
                                Console.WriteLine("                            " + role.ToString());
                            }
                            iRoleCount += 1;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("    Role                  : N/A");
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to contact the current domain..");
            }
        }

        // Args
        class ArgOptions
        {
            [Option(null, "computer")]
            public String sComp { get; set; }

            [Option(null, "object")]
            public String sObject { get; set; }

            [Option(null, "group")]
            public String sGroup { get; set; }

            [Option(null, "sid")]
            public String sSid { get; set; }

            [Option(null, "domain")]
            public String sDomain { get; set; }

            [Option(null, "user")]
            public String sUser { get; set; }

            [Option(null, "pass")]
            public String sPass { get; set; }

            [Option(null, "grant")]
            public String sGrant { get; set; }

            [Option(null, "type")]
            public String sType { get; set; }

            [Option(null, "newpass")]
            public String sNewPass { get; set; }

            [Option(null, "ntaccount")]
            public String sNtaccount { get; set; }

            [Option(null, "guid")]
            public String sGUID { get; set; }

            [Option(null, "delegation")]
            public Boolean bDelegation { get; set; }

            [Option(null, "asrep")]
            public Boolean bAsrep { get; set; }

            [Option(null, "spn")]
            public Boolean bSPN { get; set; }

            [Option(null, "dc")]
            public Boolean bDc { get; set; }

            [Option(null, "remove")]
            public Boolean bRemove { get; set; }

            [Option(null, "make")]
            public Boolean bMake { get; set; }

            [Option(null, "disable")]
            public Boolean bDisable { get; set; }

            [Option(null, "delete")]
            public Boolean bDelete { get; set; }

            [Option(null, "access")]
            public Boolean bAccess { get; set; }

            [Option(null, "help")]
            public Boolean bHelp { get; set; }
        }

        static void Main(string[] args)
        {
            var ArgOptions = new ArgOptions();
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (ArgOptions.bHelp || args.Length == 0)
                {
                    hStandIn.getHelp();
                }
                else
                {
                    if (!String.IsNullOrEmpty(ArgOptions.sComp) || !String.IsNullOrEmpty(ArgOptions.sObject) || !String.IsNullOrEmpty(ArgOptions.sGroup) || ArgOptions.bSPN || ArgOptions.bDelegation || ArgOptions.bAsrep || ArgOptions.bDc)
                    {
                        if (!String.IsNullOrEmpty(ArgOptions.sComp))
                        {
                            if (ArgOptions.bRemove)
                            {
                                removeAllowedToActOnBehalfOfOtherIdentity(ArgOptions.sComp, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (ArgOptions.bMake)
                            {
                                LDAPMakeMachineAccount(ArgOptions.sComp, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (ArgOptions.bDisable)
                            {
                                disableMachineAccount(ArgOptions.sComp, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (ArgOptions.bDelete)
                            {
                                deleteMachineAccount(ArgOptions.sComp, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sSid))
                            {
                                setAllowedToActOnBehalfOfOtherIdentity(ArgOptions.sComp, ArgOptions.sSid, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else
                            {
                                Console.WriteLine("[!] Insufficient arguments provided with --computer..");
                            }
                        }
                        else if (!String.IsNullOrEmpty(ArgOptions.sObject))
                        {
                            if (ArgOptions.bAccess)
                            {
                                getObjectAccessPermissions(ArgOptions.sObject, ArgOptions.sNtaccount, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sGrant))
                            {
                                if (!String.IsNullOrEmpty(ArgOptions.sType) && ArgOptions.sType.ToLower() != "none")
                                {
                                    try
                                    {
                                        hStandIn.AccessRequest arq = (hStandIn.AccessRequest)Enum.Parse(typeof(hStandIn.AccessRequest), ArgOptions.sType.ToLower());
                                        grantObjectAccessPermissions(ArgOptions.sObject, arq, ArgOptions.sGUID, ArgOptions.sGrant, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Invalid access premission type provided..");
                                    }
                                }
                                else if (!String.IsNullOrEmpty(ArgOptions.sGUID))
                                {
                                    grantObjectAccessPermissions(ArgOptions.sObject, hStandIn.AccessRequest.none, ArgOptions.sGUID, ArgOptions.sGrant, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                }
                                else
                                {
                                    grantObjectAccessPermissions(ArgOptions.sObject, hStandIn.AccessRequest.genericall, ArgOptions.sGUID, ArgOptions.sGrant, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                }
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sNewPass))
                            {
                                setAccountPassword(ArgOptions.sObject, ArgOptions.sNewPass, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (ArgOptions.bAsrep)
                            {
                                if (ArgOptions.bRemove)
                                {
                                    setASREP(ArgOptions.sObject, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                }
                                else
                                {
                                    setASREP(ArgOptions.sObject, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                }
                            }
                            else
                            {
                                returnObject(ArgOptions.sObject, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                        }
                        else if (!String.IsNullOrEmpty(ArgOptions.sGroup))
                        {
                            if (!String.IsNullOrEmpty(ArgOptions.sNtaccount))
                            {
                                addUserToGroup(ArgOptions.sGroup, ArgOptions.sNtaccount, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else
                            {
                                getGroupMembership(ArgOptions.sGroup, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                        }
                        else if (ArgOptions.bSPN)
                        {
                            getSPNAccounts(ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                        }
                        else if (ArgOptions.bDelegation)
                        {
                            getDelegationAccounts(ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                        }
                        else if (ArgOptions.bAsrep)
                        {
                            getASREPAccounts(ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                        }
                        else if (ArgOptions.bDc)
                        {
                            GetADDomainControllers();
                        }
                    }
                    else
                    {
                        Console.WriteLine("[!] Insufficient arguments provided..");
                    }
                }
            } else
            {
                hStandIn.getHelp();
            }
        }
    }
}
