def analyze_domain(domain):
    return {
        "domain": domain,
        **get_domain_age(domain),
        "nameservers": get_nameservers(domain),
    }