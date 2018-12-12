"""nftables_util provides nftable utility functions"""
import re
import copy

# long functions (case statements etc)
# pylint: disable=too-many-branches
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements
# long argument lists
# pylint: disable=too-many-arguments

class NonsensicalException(Exception):
    """
    This exception is thrown when creating a rule command of a non-sensical rule

    This is used in cases like a user wants to create a rule to block when
    dns_prediction == netflix.com and source_address == 192.168.1.100
    In this case we'll add this rule to both the ip and ip6 tables, but in the ip6 table
    this makes no sense and we just want this rule silently ignored without an error.
    """
    pass

def check_operation(op, array):
    """Utility function to check that op is in array"""
    if op not in array:
        raise Exception("Unsupported operation " + str(op))

def op_str(op):
    """
    Returns a command-line safe version of the operation
    Appends spaces to the beginning and end
    """
    if op == "==":
        return " "
    elif op == "!=":
        return " != "
    elif op == "<":
        return " \"<\" "
    elif op == ">":
        return " \">\" "
    elif op == "<=":
        return " \"<=\" "
    elif op == ">=":
        return " \">=\" "

def value_str(value):
    """
    Returns a nft formatted value
    If the string contains a comma, it separates into nft list
    """
    if len(value.split(",")) < 2:
        return "'" + value + "'"
    else:
        return "'{" + value + "}'"

def selector_expression(typ, family, ip_protocol=None):
    """generic helper function to build a basic nftables selector expression"""
    if typ == "IP_PROTOCOL":
        return "ip protocol"
    elif typ == "SOURCE_ADDRESS":
        if family not in ['ip', 'inet']:
            raise NonsensicalException("Ignore IPv4 family: %s" % family)
        return "ip saddr"
    elif typ == "DESTINATION_ADDRESS":
        if family not in ['ip', 'inet']:
            raise NonsensicalException("Ignore IPv4 family: %s" % family)
        return "ip daddr"
    elif typ == "SOURCE_ADDRESS_V6":
        if family not in ['ip6', 'inet']:
            raise NonsensicalException("Ignore IPv6 family: %s" % family)
        return "ip6 saddr"
    elif typ == "DESTINATION_ADDRESS_V6":
        if family not in ['ip6', 'inet']:
            raise NonsensicalException("Ignore IPv6 family: %s" % family)
        return "ip6 daddr"
    elif typ == "SOURCE_PORT":
        if ip_protocol is None:
            raise Exception("Undefined protocol with port condition")
        return ip_protocol + " sport"
    elif typ == "DESTINATION_PORT":
        if ip_protocol is None:
            raise Exception("Undefined protocol with port condition")
        return ip_protocol + " dport"

    raise Exception("Unsupported selector type " + typ)

def condition_dict_expression(table, key, field, typ, op, value):
    """A generic helper funciton to build a basic nftables dict expression"""
    if table is None:
        raise Exception("Invalid table: " + str(table))
    if key is None:
        raise Exception("Invalid key: " + str(key))
    if field is None:
        raise Exception("Invalid field: " + str(field))
    if typ in ["long_string", "bool"] and op != "==" and op != "!=":
        raise Exception("Unsupported operation " + str(op) + " for type " + typ)

    return "dict " + table.strip() + " " + key.strip() + " " + field.strip() + " " + typ.strip() + op_str(op) + value_str(value)

def condition_interface_zone_expression(mark_exp, wan_mark, intf_mark, value, op):
    """A generic helper for generating zone expressions"""
    if op != "==" and op != "!=":
        raise Exception("Unsupported operation " + str(op))
    intfs = value.split(",")
    if "wan" in intfs and len(intfs) != 1:
        # Because wan isn't a specific interface we can't use sets
        # We have no ability to check that mark and logical OR that with checking another mark
        raise Exception("\"wan\" interface condition value can not be used with other values")
    if "non_wan" in intfs and len(intfs) != 1:
        # Because non_wan isn't a specific interface we can't use sets
        # We have no ability to check that mark and logical OR that with checking another mark
        raise Exception("\"non_wan\" interface condition value can not be used with other values")

    if "wan" in intfs:
        if op == "==":
            return mark_exp + " and " + wan_mark + " != '0'"
        else:
            return mark_exp + "  and " + wan_mark + " == '0'"
    elif "non_wan" in intfs:
        if op == "==":
            return mark_exp + " and " + wan_mark + " == '0'"
        else:
            return mark_exp + " and " + wan_mark + " != '0'"
    else:
        try:
            if op == "==":
                return mark_exp + " and " + intf_mark + " " + value_str(value)
            else:
                return mark_exp + " and " + intf_mark + " != " + value_str(value)
        except ValueError:
            raise Exception("Invalid interface condition value: " + str(value))

def condition_v4address_expression(addr_str, value, op, family):
    """Generic helper for making address expressions"""
    if family not in ['ip', 'inet']:
        raise NonsensicalException("Ignore IPv4 family: %s" % family)
    if ":" in value:
        raise Exception("Invalid IPv4 value: " + str(value))
    return "ip " + addr_str + op_str(op) + value_str(value)

def condition_address_type_expression(addr_str, value, op, family):
    """Generic helper for making destination_type expressions"""
    if family not in ['ip', 'ip6', 'inet']:
        raise NonsensicalException("Ignore family: %s" % family)
    if value not in ['unspec', 'unicast', 'local', 'broadcast', 'anycast', 'multicast', 'blackhole', 'unreachable', 'prohibit']:
        raise Exception("Invalid address type value: " + str(value))
    return "fib " + addr_str + " type" + op_str(op) + value_str(value)

def condition_v6address_expression(addr_str, value, op, family):
    """Generic helper for making address expressions"""
    if family not in ['ip6', 'inet']:
        raise NonsensicalException("Ignore IPv6 family: %s" % family)
    if "." in value:
        raise Exception("Invalid IPv6 value: " + str(value))
    return "ip6 " + addr_str + op_str(op) + value_str(value)

def condition_port_expression(port_str, ip_protocol, value, op):
    """Generic helper for making port expressions"""
    if ip_protocol is None:
        raise Exception("Undefined protocol with port condition")
    return ip_protocol + " " + port_str + op_str(op) + value_str(value)

def condition_ct_state_expression(value, op):
    """Generic helper for making port expressions"""
    if "," in value:
        for val in value.split(","):
            if val not in ["established", "related", "new", "invalid"]:
                raise Exception("Invalid ct state value: %s" % val)
    else:
        if value not in ["established", "related", "new", "invalid"]:
            raise Exception("Invalid ct state value: %s" % val)
    return "ct state " + op_str(op) + " " + value

def condition_limit_rate_expression(value, op, rate_unit):
    """Generic helper for limit rate expressions"""
    if rate_unit is None:
        raise Exception("Limit rate expressions require rate_unit")
    rate_int = int(value)
    if op == "<":
        return "limit rate %d%s" % (rate_int, get_limit_rate_unit_string(rate_unit))
    else:
        return "limit rate over %d%s" % (rate_int, get_limit_rate_unit_string(rate_unit))

def condition_expression(condition, family, ip_protocol=None):
    """Build nft expressions from the JSON condition object"""
    typ = condition.get('type')
    op = condition.get('op')
    value = condition.get('value')
    unit = condition.get('rate_unit')

    if typ is None:
        raise Exception("Condition missing type: " + str(condition.get('ruleId')))
    if value is None:
        raise Exception("Condition missing value: " + str(condition.get('ruleId')))
    if op is None:
        raise Exception("Condition missing op: " + str(condition.get('ruleId')))

    if typ == "IP_PROTOCOL":
        check_operation(op, ["==", "!="])
        return "ip protocol" + op_str(op) + value_str(value.lower())
    elif typ == "SOURCE_INTERFACE_ZONE":
        return condition_interface_zone_expression("mark", "0x01000000", "0x000000ff", value, op)
    elif typ == "DESTINATION_INTERFACE_ZONE":
        return condition_interface_zone_expression("mark", "0x02000000", "0x0000ff00", value, op)
    elif typ == "SOURCE_INTERFACE_NAME":
        check_operation(op, ["==", "!="])
        return "iifname" + op_str(op) + value_str(value)
    elif typ == "DESTINATION_INTERFACE_NAME":
        check_operation(op, ["==", "!="])
        return "oifname" + op_str(op) + value_str(value)
    elif typ == "SOURCE_ADDRESS":
        return condition_v4address_expression("saddr", value, op, family)
    elif typ == "SOURCE_ADDRESS_TYPE":
        return condition_address_type_expression("saddr", value, op, family)
    elif typ == "DESTINATION_ADDRESS":
        return condition_v4address_expression("daddr", value, op, family)
    elif typ == "DESTINATION_ADDRESS_TYPE":
        return condition_address_type_expression("daddr", value, op, family)
    elif typ == "SOURCE_ADDRESS_V6":
        return condition_v6address_expression("saddr", value, op, family)
    elif typ == "DESTINATION_ADDRESS_V6":
        return condition_v6address_expression("daddr", value, op, family)
    elif typ == "SOURCE_PORT":
        return condition_port_expression("sport", ip_protocol, value, op)
    elif typ == "DESTINATION_PORT":
        return condition_port_expression("dport", ip_protocol, value, op)
    elif typ == "CLIENT_INTERFACE_ZONE":
        return condition_interface_zone_expression("ct mark", "0x01000000", "0x000000ff", value, op)
    elif typ == "SERVER_INTERFACE_ZONE":
        return condition_interface_zone_expression("ct mark", "0x02000000", "0x0000ff00", value, op)
    elif typ == "CLIENT_ADDRESS":
        return condition_dict_expression("session", "ct id", "client_address", "ipv4_addr", op, value)
    elif typ == "SERVER_ADDRESS":
        return condition_dict_expression("session", "ct id", "server_address", "ipv4_addr", op, value)
    elif typ == "LOCAL_ADDRESS":
        return condition_dict_expression("session", "ct id", "local_address", "ipv4_addr", op, value)
    elif typ == "REMOTE_ADDRESS":
        return condition_dict_expression("session", "ct id", "remote_address", "ipv4_addr", op, value)
    elif typ == "CLIENT_ADDRESS_V6":
        return condition_dict_expression("session", "ct id", "client_address", "ipv6_addr", op, value)
    elif typ == "SERVER_ADDRESS_V6":
        return condition_dict_expression("session", "ct id", "server_address", "ipv6_addr", op, value)
    elif typ == "LOCAL_ADDRESS_V6":
        return condition_dict_expression("session", "ct id", "local_address", "ipv6_addr", op, value)
    elif typ == "REMOTE_ADDRESS_V6":
        return condition_dict_expression("session", "ct id", "remote_address", "ipv6_addr", op, value)
    elif typ == "CLIENT_PORT":
        return condition_dict_expression("session", "ct id", "client_port", "integer", op, value)
    elif typ == "SERVER_PORT":
        return condition_dict_expression("session", "ct id", "server_port", "integer", op, value)
    elif typ == "LOCAL_PORT":
        return condition_dict_expression("session", "ct id", "local_port", "integer", op, value)
    elif typ == "REMOTE_PORT":
        return condition_dict_expression("session", "ct id", "remote_port", "integer", op, value)
    elif typ == "CLIENT_HOSTNAME":
        return condition_dict_expression("session", "ct id", "client_hostname", "long_string", op, value)
    elif typ == "SERVER_HOSTNAME":
        return condition_dict_expression("session", "ct id", "server_hostname", "long_string", op, value)
    elif typ == "LOCAL_HOSTNAME":
        return condition_dict_expression("session", "ct id", "local_hostname", "long_string", op, value)
    elif typ == "REMOTE_HOSTNAME":
        return condition_dict_expression("session", "ct id", "remote_hostname", "long_string", op, value)
    elif typ == "CLIENT_USERNAME":
        return condition_dict_expression("session", "ct id", "client_username", "long_string", op, value)
    elif typ == "SERVER_USERNAME":
        return condition_dict_expression("session", "ct id", "server_username", "long_string", op, value)
    elif typ == "LOCAL_USERNAME":
        return condition_dict_expression("session", "ct id", "local_username", "long_string", op, value)
    elif typ == "REMOTE_USERNAME":
        return condition_dict_expression("session", "ct id", "remote_username", "long_string", op, value)
    elif typ == "CT_STATE":
        return condition_ct_state_expression(value, op)
    elif typ == "LIMIT_RATE":
        check_operation(op, [">", "<"])
        return condition_limit_rate_expression(value, op, unit)
    raise Exception("Unsupported condition type " + typ + " " + str(condition.get('ruleId')))

def conditions_expression(conditions, family):
    """
    This method takes a list of conditions from a rule and translates them into a string containing the nftables conditions
    It returns a list of strings, because some set of conditions require multiple nftables rules
    Example input: ['type':'SOURCE_INTERFACE', 'value':'1'] -> "ct mark and 0xff == 0x01"
    Example input: ['type':'DESTINATION_PORT', 'value':'123'] -> "tcp dport 123"
    """
    if conditions is None:
        return ""

    # set has_protocol_condition to True if this rule as an "IP_PROTOCOL" condition
    ip_protocol = None
    for condition in conditions:
        if condition.get('type') == 'IP_PROTOCOL' and condition.get('op') == '==' and condition.get('value') != None and "," not in condition.get('value'):
            ip_protocol = condition.get('value')

    strcat = ""
    for condition in conditions:

        group_selector = condition.get('group_selector')
        if group_selector != None:
            conditions_expression.meter_id = getattr(conditions_expression, 'meter_id', 0) + 1
            strcat = strcat + " meter meter-%d { %s" % (conditions_expression.meter_id, selector_expression(group_selector, family, ip_protocol=ip_protocol))

        add_str = condition_expression(condition, family, ip_protocol=ip_protocol)
        if add_str != "":
            strcat = strcat + " " + add_str

        if group_selector != None:
            strcat = strcat + " }"

    return strcat.strip()

def action_expression(json_action, family):
    """This method takes an method json object and provides the nft expression as a string"""
    check_action(json_action)
    typ = json_action.get('type')

    if typ == "REJECT":
        return "reject"
    elif typ == "DROP":
        return "drop"
    elif typ == "ACCEPT":
        return "accept"
    elif typ == "RETURN":
        return "return"
    elif typ == "DNAT":
        addr = json_action.get('dnat_address')
        port = json_action.get('dnat_port')
        if addr is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        if family == "ip" and ":" in addr:
            raise NonsensicalException("Ignore IPv6 for IPv4 DNAT: %s" % family)
        if family == "ip6" and "." in addr:
            raise NonsensicalException("Ignore IPv4 for IPv6 DNAT: %s" % family)
        port_int = None
        if port != None:
            port_int = int(port)
        if port_int != None:
            return "dnat to %s:%i" % (addr, port_int)
        else:
            return "dnat to %s" % (addr)
    elif typ == "SNAT":
        addr = json_action.get('snat_address')
        if addr is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        if family == "ip" and ":" in addr:
            raise NonsensicalException("Ignore IPv6 for IPv4 SNAT: %s" % family)
        if family == "ip6" and "." in addr:
            raise NonsensicalException("Ignore IPv4 for IPv6 SNAT: %s" % family)
        return "snat to %s" % (addr)
    elif typ == "MASQUERADE":
        return "masquerade"
    elif typ == "JUMP":
        chain = json_action.get('chain')
        if chain is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        return "jump " + chain
    elif typ == "GOTO":
        chain = json_action.get('chain')
        if chain is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        return "goto " + chain
    elif typ == "SET_PRIORITY":
        priority = json_action.get('priority')
        if priority is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        priority_int = int(priority) & 0xff
        return "meta mark set \"mark and 0xff00ffff or 0x00%s0000\"" % ('{:02x}'.format(priority_int))
    elif typ == "WAN_DESTINATION":
        destination = json_action.get('destination')
        if destination is None:
            raise Exception("Invalid action: Missing required parameter for action type " + str(typ))
        destination_int = int(destination) & 0xff
        return "meta mark set \"mark and 0xffff00ff or 0x0000%s00\"" % ('{:02x}'.format(destination_int))
    else:
        raise Exception("Unknown action type: " + str(json_action))

def rule_expression(json_rule, family):
    """Builds an nft rule from the JSON rule object"""
    check_rule(json_rule)

    rule_exp = ""
    conditions = json_rule.get('conditions')
    if conditions != None:
        rule_exp = rule_exp + " " + conditions_expression(conditions, family)

    action_exp = action_expression(json_rule.get('action'), family)
    rule_exp = rule_exp + " " + action_exp

    return rule_exp[1:]

def rule_cmd(json_rule, family, table, chain):
    """This method takes a rule json object and provides the nft command"""
    check_rule(json_rule)

    if not json_rule.get('enabled'):
        return None

    try:
        cmd = "nft add rule " + family + " " + table + " " + chain + " " + rule_expression(json_rule, family)
        return cmd
    except NonsensicalException:
        return None
    except:
        raise

def chain_create_cmd(json_chain, family, table):
    """Return the nft command to create this chain"""
    check_chain(json_chain)
    check_family(family)

    name = json_chain.get('name')

    # vote is only valid in the ip, ip6 familyt, but the vote table is ip,ip6,inet just ignore inet
    if json_chain.get('base') and json_chain.get('type') == "route" and family == "inet":
        raise NonsensicalException("Ignore inet/route chains")

    if json_chain.get('base'):
        typ = json_chain.get('type')
        hook = json_chain.get('hook')
        priority = json_chain.get('priority')
        if typ is None or typ not in ["filter", "route", "nat"]:
            raise Exception("Invalid type (%s) for chain %s" % (typ, name))
        if hook is None or hook not in ["prerouting", "input", "forward", "output", "postrouting", "ingress"]:
            raise Exception("Invalid hook (%s) for chain %s" % (hook, name))
        if priority is None or priority < -500 or priority > 500:
            raise Exception("Invalid priority (%d) for chain %s" % (priority, name))
        return "nft add chain %s %s %s \"{ type %s hook %s priority %d ; }\"" % (family, table, name, typ, hook, priority)
    else:
        return "nft add chain %s %s %s" % (family, table, name)

def chain_rules_cmds(json_chain, family, table):
    """Return all the commands to create and populate this chain"""
    check_chain(json_chain)

    # vote is only valid in the ip, ip6 familyt, but the vote table is ip,ip6,inet just ignore inet
    if json_chain.get('base') and json_chain.get('type') == "route" and family == "inet":
        raise NonsensicalException("Ignore inet/route chains")

    cmds = []
    for rule in json_chain['rules']:
        rule_cmd_str = rule_cmd(rule, family, table, json_chain['name'])
        if rule_cmd_str != None:
            cmds.append(rule_cmd_str)
    return '\n'.join(cmds)

def table_create_cmd(json_table):
    """Return the nft command to create this table"""
    check_table(json_table)
    return "nft add table %s %s" % (json_table.get('family'), json_table.get('name'))

def table_flush_cmd(json_table):
    """Return the nft command to flush this table"""
    cmd = table_create_cmd(json_table).replace(" add ", " flush ")
    return cmd.replace(" add ", " flush ")

def table_delete_cmd(json_table):
    """Return the nft command to delete this table"""
    cmd = table_create_cmd(json_table)
    return cmd.replace(" add ", " delete ") + " 2>/dev/null || true"

def table_all_cmds(json_table):
    """Return all the commands to create, flush, and populate this table"""
    check_table(json_table, allow_multiple_families=True)
    cmds = []
    name = json_table.get('name')
    family = json_table.get('family')
    if "," in family:
        families = family.split(",")
        strcat = ""
        for fam in families:
            # make shallow copies and create separate tables
            json_table_fam = copy.copy(json_table)
            json_table_fam['family'] = fam
            strcat += table_all_cmds(json_table_fam) + "\n"
        return strcat

    cmds.append(table_delete_cmd(json_table))
    cmds.append(table_create_cmd(json_table))
    for json_chain in json_table.get('chains'):
        try:
            cmds.append(chain_create_cmd(json_chain, family, name))
        except NonsensicalException:
            pass
    for json_chain in json_table.get('chains'):
        try:
            cmds.append(chain_rules_cmds(json_chain, family, name))
        except NonsensicalException:
            pass
    return '\n'.join(cmds)

def check_chain(json_chain):
    """Check the provided chain has the required attributes, throw exception if not"""
    if json_chain is None:
        raise Exception("Invalid chain: null")
    name = json_chain.get('name')
    rules = json_chain.get('rules')
    if name is None or not legal_nft_name(name):
        raise Exception("Invalid name (%s) for chain" % name)
    if rules is None:
        raise Exception("Invalid rules (null) in chain %s" % name)
    return

def check_rule(json_rule):
    """Check the provided rule has the required attributes, throw exception if not"""
    if json_rule is None:
        raise Exception("Invalid rule: null")
    rule_id = json_rule.get('ruleId')
    if rule_id is None:
        raise Exception("Missing ruleId: " + str(json_rule))

def check_table(json_table, allow_multiple_families=False):
    """Check the provided table has the required attributes, throw exception if not"""
    if json_table is None:
        raise Exception("Invalid table: null")
    name = json_table.get('name')
    family = json_table.get('family')
    chains = json_table.get('chains')
    if name is None or not legal_nft_name(name):
        raise Exception("Invalid name (%s) in table" % name)
    if allow_multiple_families:
        for fam in family.split(","):
            if fam is None or fam not in ['ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev']:
                raise Exception("Invalid family (%s) for table %s" % (fam, name))
    else:
        if family is None or family not in ['ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev']:
            raise Exception("Invalid family (%s) for table %s" % (family, name))
    if chains is None:
        raise Exception("Invalid chains (null) for table %s" % name)

def check_action(json_action):
    """Check the provided action has the required attributes, throw exception if not"""
    if json_action is None:
        raise Exception("Invalid action: null")
    if json_action.get('type') is None:
        raise Exception("Invalid action type: null")

def check_family(family):
    """Check the provided string is a valid family - throw exception if not"""
    if family is None:
        raise Exception("Invalid family: null")
    if family not in ['ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev']:
        raise Exception("Invalid family (" + family + ")")

def legal_nft_name(name):
    """Return true if a legal nft name, Fales otherwise"""
    if name is None:
        return False
    match = re.match("[a-z-]+", name)
    return match is not None

def get_limit_rate_unit_string(unit):
    """Get the nftable syntax for a rate limit constant"""
    return {
        "PACKETS_PER_SECOND": "/second",
        "PACKETS_PER_MINUTE": "/minute",
        "PACKETS_PER_HOUR": "/hour",
        "PACKETS_PER_DAY": "/day",
        "PACKETS_PER_WEEK": "/week",
        "BYTES_PER_SECOND": " bytes/second",
        "KBYTES_PER_SECOND": " kbytes/second",
        "MBYTES_PER_SECOND": " mbytes/second",
    }.get(unit, "/second")
