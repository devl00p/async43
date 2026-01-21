NO_SUCH_RECORD_LABELS = [
    "No whois server is known for this kind of object.",
    "No Data Found\r\n",
    "Domain not found.\r\n",
    "The queried object does not exist:",
    "Domain Status: No Object Found\n",
    " is available for registration\r\n",
    "Not find MatchingRecord\r\n",
    "No matching record.\r\n",
    "% No match found.\r\n",
    ">>> This name is not available for registration:\r\n",
    "Not Found.\n",
    "% No entries found.\r\n",
    "\nNo match for ",
    "No Found\n",
    "%% NOT FOUND\n\n",
    "registration status: invalid\n",
    ", not found in database\n",
    "No data was found to match the request criteria.\n",
    "*** Nothing found for this query.",
    "No information was found matching that query.\n",
    "The requested domain was not found in the Registry",
    "NO OBJECT FOUND!\n",
    "No entries found for domain ",
    "No entries found.\n",
    "object does not exist\r\n",
    "DOMAIN NOT FOUND",
    "No record found for '",
    "Not found: ",
    "No Match for domain: ",
    "The domain name you requested was not found in our database.\n",
    "TLD is not supported.\r\n",
    "Message: No Object Found\n",
    "Domain Status: free\r",
    "Available: Yes.",
    "%ERROR:102: Invalid domain name",
    "\nNo match\n",
    " is free\r\n",
    "This query returned 0 objects.",
    "The domain you requested is not known in Freenoms database.",
    " was not found.\r\n",
    " - No Match\n",
    " is available for purchase\n",
    ">>> The domain contains special characters not allowed.\n",
    "registration status: invalid\n",
    "Wrong top level domain name in query\n",
    "NOT FOUND",  # full text
    "No match for \"",
    "\nNo match for ",
    "Error message: The domain name requested has usage restrictions applied to it.",
    "-7: %Invalid pattern",
    "Domain Status: Prohibited String - Domain Cannot Be Registered",
    "%ERROR: Invalid request",
    "The domain has not been registered.\n",
    "This query returned 0 objects",
    "The domain you requested is not known",
    "This domain is currently not available for registration",
    "TLD is not supported",
]

TEMP_ERROR = [
    "Server can't process your request at the moment",
    "Server is busy now, please try again later.",
]

LEGAL_MENTIONS = [
    "The compilation, repackaging, dissemination",
    "The data in Nameshield Whois database",
    "TERMS OF USE:",
    "NOTICE:",
    "By submitting a Whois query",
    "commercial advertising or solicitations via e-mail",
    "Nameshield reserves the right to restrict",
    "order to protect the privacy of Registrants",
    "URL of the ICANN Whois Inaccuracy Complaint Form",
    "You have no right to access our WHOIS database via high capacity",
    "You agree that you may use this Data only for lawful purposes",
    "circumstances will you",
]

SCHEMA_MAPPING = {
    "domain": ["domain name", "domain", "dn", "nom de domaine"],
    "registrar_iana_id": ["registrar iana id", "注册商互联网号码分配当局(iana)id(sponsoring registrar iana id)"],
    "dnssec": ["dnssec", "域名系统安全扩展协议(dnssec)", "dnssec signed"],
    "dates.created": [
        "creation date", "created", "registered", "created date", "record created", "domain created", "registered on",
        "created-date", "注册时间(creation date)", "registration time", "registration date", "created on"
    ],
    "dates.updated": [
        "updated date", "last update", "last modified", "changed", "modified", "dernière modification",
        "record last updated on", "updated", "modification date", "updated-date", "expiration-date",
        "renewed on", "更新时间(Updated Date)", "last updated on"
    ],
    "dates.expires": [
        "registry expiry date", "expiration date", "expiry", "expires", "date d'expiration", "expire date",
        "record expires on", "expires on", "valid until", "到期时间(registry expiry date)",
        "Date out of quarantine", "expiration time", "expiry date", "free-date",
    ],
    "nameservers": [
        "name server", "nserver", "serveur de noms", "primary server", "secondary server", "dns", "hostname",
        "ns 1", "ns 2", "ns 3", "ns 4", "ns 5", "ns 6", "ns 7", "ns 8", "ns 9", "ns 10", "域名服务器(name server)",
        "nameserver"
    ],
    "status": ["domain status", "status", "registration status", "域状态(domain status)"],

    # ABUSE
    "contacts.abuse.email": ["abuse.email", "registrar abuse contact email"],
    "contacts.abuse.phone": ["registrar abuse contact phone", "abuse-phone", "abuse tel"],
    "contacts.abuse.id": ["abuse handle", "abuse nic handle"],

    # ADMIN
    "contacts.administrative.email": [
        "admin.email", "admin email", "admin.contact email", "管理联系人电子邮件(admin email)",
        "administrative email",
    ],
    "contacts.administrative.name": [
        "admin.name", "admin.contact", "admin name", "管理联系人姓名(admin name)", "admin contact",
        "administrative name", "administrative contact"
    ],
    "contacts.administrative.street": [
        "admin.street", "admin street", "admin.address", "admin address", "管理联系人所在街道(admin street)",
        "administrative street", "administrative address",
    ],
    "contacts.administrative.city": [
        "admin.city", "admin city", "管理联系人所在城市(admin city)",
        "administrative city",
    ],
    "contacts.administrative.postal_code": [
        "admin.postal code", "admin postal code", "admin zipcode", "管理联系人邮政编码(admin postal code)",
        "administrative postal code", "administrative zipcode"
    ],
    "contacts.administrative.state": [
        "admin.state", "admin state/province", "管理联系人所在州/省(admin state/province)", "administrative state",
        "administrative state/province",
    ],
    "contacts.administrative.country": [
        "admin.country", "admin country", "管理联系人所在国家和地区(admin country)", "admin country code",
        "administrative country", "administrative country code",
    ],
    "contacts.administrative.organization": [
        "admin.organization", "admin organization", "管理联系人组织(admin organization)", "administrative organization",
    ],
    "contacts.administrative.organization_id": ["admin organization id", "administrative organization id"],
    "contacts.administrative.id": [
        "admin handle", "admin nic handle", "administrative nic handle", "administrative handle"
    ],
    "contacts.administrative.phone": [
        "admin.phone", "admin phone", "管理联系人电话(admin phone)", "admin tel", "administrative tel",
        "administrative phone"
    ],
    "contacts.administrative.fax": ["admin.fax", "admin fax", "管理联系人传真(admin fax)", "administrative fax"],
    "contacts.administrative.created": ["admin created", "administrative created"],
    "contacts.administrative.updated": ["admin updated", "administrative updated"],

    # BILLING
    "contacts.billing.email": [
        "billing.email", "billing email", "注册联系人电子邮件(billing email)"
    ],
    "contacts.billing.name": [
        "billing.name", "billing.contact", "注册联系人姓名(billing name)", "billing contact"
    ],
    "contacts.billing.street": [
        "billing.street", "billing street", "billing address", "注册联系人所在街道(billing street)"
    ],
    "contacts.billing.city": [
        "billing.city", "billing city", "注册联系人所在城市(billing city)"
    ],
    "contacts.billing.postal_code": [
        "billing.postal code", "billing postal code", "注册联系人邮政编码(billing postal code)"
    ],
    "contacts.billing.state": [
        "billing.state", "billing state/province", "注册联系人所在州/省(billing state/province)"
    ],
    "contacts.billing.country": [
        "billing.country", "billing country", "注册联系人所在国家和地区(billing country)"
    ],
    "contacts.billing.organization": [
        "billing.organization", "billing organization", "注册联系人组织(billing organization)"
    ],
    "contacts.billing.organization_id": ["billing organization id"],
    "contacts.billing.id": ["billing handle", "billing nic handle"],
    "contacts.billing.phone": [
        "billing.phone", "billing phone", "注册联系人电话(billing phone)", "billing tel"
    ],
    "contacts.billing.fax": ["billing.fax", "billing fax", "注册联系人传真(billing fax)"],

    # REGISTRANT
    "contacts.registrant.email": [
        "registrant.email", "registrant email", "owner email",
        "注册联系人电子邮件(registrant email)", "registrant contact email",  # "email", "courriel",
    ],
    "contacts.registrant.id": ["registrant id", "domain registrant", "registrant handle", "registrant nic handle"],
    "contacts.registrant.name": [
        "registrant.name", "registrant.contact", "registrant name", "owner name",
        "注册联系人姓名(registrant name)", "registrant", "registrant registrant", "registrant contact",
    ],
    "contacts.registrant.street": [
        "registrant.street", "registrant street", "registrant postal address",
        "owner address", "registrant address", "注册联系人所在街道(registrant street)",
        #  "address", "postal address", "street address", "street"

    ],
    "contacts.registrant.city": [
        "registrant.city", "registrant city", "registrant ville", "registrant city", "owner city",
        "注册联系人所在城市(registrant city)"
    ],
    "contacts.registrant.postal_code": [
        "registrant.postal code", "registrant postal code", "registrant postalcode", "registrant postal",
        "owner zipcode", "registrant postal-code", "注册联系人邮政编码(registrant postal code)",
        #  "postal code",
    ],
    "contacts.registrant.state": [
        "registrant.state", "registrant state/province", "registrant state",
        "注册联系人所在州/省(registrant state/province)"
    ],
    "contacts.registrant.country": [
        "registrant.country", "registrant country", "registrant pays", "owner country code", "registrant country code",
        "registrant country-loc", "注册联系人所在国家和地区(registrant country)"
    ],
    "contacts.registrant.organization": [
        "registrant.organization", "registrant organization", "registrant org", "注册联系人组织(registrant organization)"
    ],
    "contacts.registrant.organization_id": [
        "registrant.organization_id", "registrant organization id", "registrant org id",
    ],
    "contacts.registrant.phone": [
        "registrant.phone", "registrant phone", "registrant téléphone", "注册联系人电话(registrant phone)",
        "registrant tel"
    ],
    "contacts.registrant.fax": ["registrant.fax", "registrant fax", "注册联系人传真(registrant fax)"],

    # REGISTRAR
    "registrar.name": [
        "registrar.name", "registrar.contact", "registrar name", "技术联系人姓名(registrar name)", "registrar contact"
    ],
    "registrar.id": ["registrar handle", "registrar nic handle"],
    "registrar.url": ["registrar url", "registrar web"],
    "registrar.email": [
        "registrar.email", "registrar.contact email", "registrar email", "registrar contact email",
        "技术联系人电子邮件(registrar email)"
    ],
    "registrar.street": [
        "registrar.street", "registrar street", "registrar.address", "技术联系人所在街道(registrar street)"
    ],
    "registrar.city": ["registrar.city", "registrar city", "技术联系人所在城市(registrar city)"],
    "registrar.postal_code": [
        "registrar.postal code", "registrar postal code", "技术联系人邮政编码(registrar postal code)"
    ],
    "registrar.state": ["registrar.state", "registrar state/province", "技术联系人所在州/省(registrar state/province)"],
    "registrar.country": [
        "registrar.country", "registrar country", "技术联系人所在国家和地区(registrar country)", "registrar country code"
    ],
    "registrar.organization": [
        "registrar.organization", "registrar organization", "registrar contact organisation",
        "技术联系人组织(registrar organization)"
    ],
    "registrar.organization_id": ["registrar organization id"],
    "registrar.phone": ["registrar.phone", "registrar phone", "技术联系人电话(registrar phone)", "registrar tel"],
    "registrar.fax": ["registrar.fax", "registrar fax", "技术联系人传真(registrar fax)"],
    "registrar.created": ["registrar created"],
    "registrar.updated": ["registrar updated"],

    # TECH
    "contacts.technical.email": [
        "tech.email", "technical.contact email", "tech email", "tech contact email", "技术联系人电子邮件(tech email)",
        "technical email",
    ],
    "contacts.technical.name": [
        "tech.name", "tech.contact", "tech name", "技术联系人姓名(tech name)", "technical contact", "technical name",
    ],
    "contacts.technical.id": ["technical handle", "technical nic handle"],
    "contacts.technical.street": [
        "tech.street", "tech street", "tech.address", "技术联系人所在街道(tech street)",
        "tech address", "technical street", "technical address"
    ],
    "contacts.technical.city": ["tech.city", "tech city", "技术联系人所在城市(tech city)", "technical city"],
    "contacts.technical.postal_code": [
        "tech.postal code", "tech postal code", "技术联系人邮政编码(tech postal code)", "technical postal code",
    ],
    "contacts.technical.state": [
        "tech.state", "tech state/province", "技术联系人所在州/省(tech state/province)", "technical state",
    ],
    "contacts.technical.country": [
        "tech.country", "tech country", "技术联系人所在国家和地区(tech country)", "tech country code", "technical country",
        "technical country code",
    ],
    "contacts.technical.organization": [
        "tech.organization", "tech organization", "tech contact organisation", "技术联系人组织(tech organization)",
        "technical organization",
    ],
    "contacts.technical.organization_id": ["tech organization id", "technical organization id"],
    "contacts.technical.phone": [
        "tech.phone", "tech phone", "技术联系人电话(tech phone)", "tech tel", "technical phone", "technical tel"],
    "contacts.technical.fax": ["tech.fax", "tech fax", "技术联系人传真(tech fax)", "technical fax"],
    "contacts.technical.created": ["tech created", "technical created"],
    "contacts.technical.updated": ["tech updated", "technical updated"],

    "SECTION_ADMINISTRATIVE": ["administrative contact", "admin contact"],
    "SECTION_TECHNICAL": ["technical contact", "tech contact", "technical contacts"],
    "SECTION_REGISTRANT": ["registrant", "registrant contact", "holder", "domain registrant", "holder of domain name"],
    "SECTION_BILLING": ["billing", "billing contact"],
    "SECTION_REGISTRAR": ["registrar", "registrar contact"],
    "SECTION_ABUSE": ["abuse", "abuse contact"],
}
