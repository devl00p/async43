from async43.parsers.base import WhoisEntry
from async43.exceptions import WhoisDomainNotFoundError

import async43.parsers.idn as idn
import async43.parsers.classics as classics
import async43.parsers.cctld as cctld
import async43.parsers.gtld as gtld

TLD_PARSER_MAP = {
    # Classics
    "com": classics.WhoisCom,
    "edu": classics.WhoisEdu,
    "info": classics.WhoisInfo,
    "net": classics.WhoisNet,
    "org": classics.WhoisOrg,

    # ccTLDs (A-Z)
    "ae": cctld.WhoisAe,
    "ai": cctld.WhoisAi,
    "ar": cctld.WhoisAr,
    "at": cctld.WhoisAt,
    "au": cctld.WhoisAU,
    "be": cctld.WhoisBe,
    "bg": cctld.WhoisBg,
    "br": cctld.WhoisBr,
    "bw": cctld.WhoisBw,
    "by": cctld.WhoisBy,
    "bz": cctld.WhoisBz,
    "ca": cctld.WhoisCa,
    "ch": cctld.WhoisChLi,
    "cl": cctld.WhoisCl,
    "cm": cctld.WhoisCm,
    "cn": cctld.WhoisCn,
    "co": cctld.WhoisCo,
    "cr": cctld.WhoisCr,
    "cz": cctld.WhoisCz,
    "de": cctld.WhoisDe,
    "dk": cctld.WhoisDk,
    "do": cctld.WhoisDo,
    "ee": cctld.WhoisEe,
    "eu": cctld.WhoisEu,
    "fi": cctld.WhoisFi,
    "fr": cctld.WhoisFr,
    "ga": cctld.WhoisGa,
    "gg": cctld.WhoisGg,
    "hr": cctld.WhoisHr,
    "hn": cctld.WhoisHn,
    "hk": cctld.WhoisHk,
    "hu": cctld.WhoisHu,
    "id": cctld.WhoisID,
    "ie": cctld.WhoisIe,
    "il": cctld.WhoisIl,
    "in": cctld.WhoisIn,
    "io": cctld.WhoisIo,
    "ir": cctld.WhoisIR,
    "is": cctld.WhoisIs,
    "it": cctld.WhoisIt,
    "jp": cctld.WhoisJp,
    "kg": cctld.WhoisKg,
    "kr": cctld.WhoisKr,
    "kz": cctld.WhoisKZ,
    "li": cctld.WhoisChLi,
    "lt": cctld.WhoisLt,
    "lu": cctld.WhoisLu,
    "lv": cctld.WhoisLv,
    "me": cctld.WhoisMe,
    "ml": cctld.WhoisML,
    "mx": cctld.WhoisMx,
    "nl": cctld.WhoisNl,
    "no": cctld.WhoisNo,
    "nu": cctld.WhoisSe,  # .nu géré par le parser .se
    "nz": cctld.WhoisNz,
    "pe": cctld.WhoisPe,
    "pl": cctld.WhoisPl,
    "pt": cctld.WhoisPt,
    "ro": cctld.WhoisRo,
    "rs": cctld.WhoisRs,
    "ru": cctld.WhoisRu,
    "sa": cctld.WhoisSa,
    "se": cctld.WhoisSe,
    "sg": cctld.WhoisSG,
    "si": cctld.WhoisSi,
    "sk": cctld.WhoisSK,
    "su": cctld.WhoisSu,
    "td": cctld.WhoisTD,
    "tn": cctld.WhoisTN,
    "tr": cctld.WhoisTr,
    "tw": cctld.WhoisTw,
    "ua": cctld.WhoisUA,
    "uk": cctld.WhoisUk,
    "us": cctld.WhoisUs,
    "ve": cctld.WhoisVe,
    "za": cctld.WhoisZa,

    # gTLDs
    "app": gtld.WhoisApp,
    "biz": gtld.WhoisBiz,
    "cat": gtld.WhoisCat,
    "city": gtld.WhoisCity,
    "design": gtld.WhoisDesign,
    "group": gtld.WhoisGroup,
    "jobs": gtld.WhoisJobs,
    "lat": gtld.WhoisLat,
    "life": gtld.WhoisLife,
    "market": gtld.WhoisMarket,
    "mobi": gtld.WhoisMobi,
    "money": gtld.WhoisMoney,
    "name": gtld.WhoisName,
    "online": gtld.WhoisOnline,
    "ooo": gtld.WhoisOoo,
    "site": gtld.WhoisSite,
    "space": gtld.WhoisSpace,
    "studio": gtld.WhoisStudio,
    "style": gtld.WhoisStyle,
    "website": gtld.WhoisWebsite,
    "xyz": gtld.WhoisXyz,

    # IDNs
    "рф": cctld.WhoisRf,
    "рус": idn.WhoisPyc,
    "xn--p1acf": idn.WhoisPyc,
    "укр": idn.WhoisUkr,
    "xn--j1amh": idn.WhoisUkr,
    "中国": idn.WhoisZhongGuo,
}

def load(domain: str, text: str):
    """Given whois output in ``text``, return an instance of ``WhoisEntry``
    that represents its parsed contents.
    """
    if text.strip() == "No whois server is known for this kind of object.":
        raise WhoisDomainNotFoundError(text)

    domain = domain.lower()

    if domain.endswith(".pp.ua"):
        return cctld.WhoisPpUa(domain, text)

    tld = domain.split('.')[-1]
    parser_class = TLD_PARSER_MAP.get(tld)

    if parser_class:
        return parser_class(domain, text)

    return WhoisEntry(domain, text)
