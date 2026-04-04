def get_smb_security_commands():
    return [

        # Vuln-Checks
        {"toolname": "nxc", "creds_required": False, "vuln": "zerologon",
         "parameters": {"username": "", "password": "", "module": "zerologon"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "nopac",
         "parameters": {"module": "nopac"}},

        {"toolname": "nxc", "creds_required": False, "vuln": "printnightmare",
         "parameters": {"username": "", "password": "", "module": "printnightmare"}},

        {"toolname": "nxc", "creds_required": False, "vuln": "smbghost",
         "parameters": {"username": "", "password": "", "module": "smbghost"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "ntlm_reflection",
         "parameters": {"module": "ntlm_reflection"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "autologon-info",
         "parameters": {"module": "gpp_autologin"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "PW_GPO_Policy",
         "parameters": {"module": "gpp_password"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "AD_PW_POLICY",
         "parameters": {"extra_args": "--pass-pol"}},

        {"toolname": "nxc", "creds_required": False, "vuln": "coerce_plus",
         "parameters": {"username": "", "password": "", "module": "coerce_plus"}},

        # SMB Null Sessions
        {"toolname": "nxc", "creds_required": False, "vuln": "SMB Null Session",
         "parameters": {"username": "", "password": ""}},

        # Guest Logon
        {"toolname": "nxc", "creds_required": False, "vuln": "SMB Guest Logon",
         "parameters": {"username": "a", "password": ""}},
    ]


def get_ldap_security_commands():
    return [

        # Vuln-Checks
        {"toolname": "nxc", "creds_required": False, "vuln": "asreproasting",
         "parameters": {"protocol": "ldap", "module": "zerologon"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "asreproasting",
         "parameters": {"protocol": "ldap", "extra_args": "--asreproast"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "Get-User-Desc",
         "parameters": {"protocol": "ldap", "module": "get-desc-users"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "User-PW",
         "parameters": {"protocol": "ldap", "module": "get-userPassword"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "Unix-PW",
         "parameters": {"protocol": "ldap", "module": "get-unixUserPassword"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "ADCS",
         "parameters": {"protocol": "ldap", "module": "adcs"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "Domain Trust",
         "parameters": {"protocol": "ldap", "module": "enum_trusts"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "LAPS",
         "parameters": {"protocol": "ldap", "module": "laps"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "LDAP-Check",
         "parameters": {"protocol": "ldap", "module": "ldap-checker"}},

        {"toolname": "nxc", "creds_required": True, "vuln": "Machine-Quota",
         "parameters": {"protocol": "ldap", "module": "maq"}},

    ]
