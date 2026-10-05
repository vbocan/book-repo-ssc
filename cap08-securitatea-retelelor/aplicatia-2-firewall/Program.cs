using System.Net;

// Definirea setului de reguli
var rules = new List<FirewallRule>
{
    new(10, "PERMIT", "any", "192.168.1.10", "TCP", 443,
        "Permite HTTPS către serverul web"),
    new(20, "PERMIT", "any", "192.168.1.10", "TCP", 80,
        "Permite HTTP către serverul web"),
    new(30, "DENY", "any", "192.168.1.20", "TCP", 3306,
        "Blochează accesul extern la MySQL"),
    new(40, "PERMIT", "192.168.1.0/24", "192.168.1.20", "TCP", 3306,
        "Permite accesul intern la MySQL"),
    new(50, "PERMIT", "10.0.0.0/8", "192.168.1.0/24", "TCP", 22,
        "Permite SSH de la rețeaua de management"),
    new(60, "DENY", "any", "any", "any", -1,
        "Deny implicit: blochează tot restul"),
    new(70, "PERMIT", "172.16.0.5", "192.168.1.10", "TCP", 8080,
        "Permite accesul de monitoring")  // Această regulă va fi umbrită!
};

// Pachete de test
var testPackets = new List<NetworkPacket>
{
    new("203.0.113.50", "192.168.1.10", 52341, 443, "TCP"),
    new("203.0.113.50", "192.168.1.20", 48721, 3306, "TCP"),
    new("192.168.1.5", "192.168.1.20", 55012, 3306, "TCP"),
    new("10.0.0.100", "192.168.1.15", 33001, 22, "TCP"),
    new("203.0.113.50", "192.168.1.10", 60123, 22, "TCP"),
    new("172.16.0.5", "192.168.1.10", 44001, 8080, "TCP"),
};

Console.WriteLine("=== Evaluare pachete ===\n");
Console.WriteLine($"{"Sursă",-18} {"Dest",-18} {"Port",-6} {"Acțiune",-8} " +
                  $"{"Regulă",-7} {"Motiv"}");
Console.WriteLine(new string('-', 90));

foreach (var packet in testPackets)
{
    var (action, ruleNum, desc) = EvaluatePacket(packet, rules);
    Console.WriteLine($"{packet.SourceIP,-18} {packet.DestIP,-18} " +
                      $"{packet.DestPort,-6} {action,-8} #{ruleNum,-6} {desc}");
}

// Analiza umbririi regulilor
DetectShadowing(rules);

Console.WriteLine("\n=== Statistici ===");
int permitted = testPackets.Count(p => EvaluatePacket(p, rules).action == "PERMIT");
int denied = testPackets.Count(p => EvaluatePacket(p, rules).action == "DENY");
Console.WriteLine($"Pachete permise: {permitted}/{testPackets.Count}");
Console.WriteLine($"Pachete blocate: {denied}/{testPackets.Count}");

// Motor de evaluare a regulilor
static bool MatchesIP(string ruleIP, string packetIP)
{
    if (ruleIP == "any") return true;
    if (ruleIP.Contains('/'))
    {
        // Verificare CIDR simplificată
        var parts = ruleIP.Split('/');
        var networkAddress = IPAddress.Parse(parts[0]);
        int prefixLength = int.Parse(parts[1]);
        var packetAddress = IPAddress.Parse(packetIP);

        byte[] networkBytes = networkAddress.GetAddressBytes();
        byte[] packetBytes = packetAddress.GetAddressBytes();

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
            if (networkBytes[i] != packetBytes[i]) return false;

        if (remainingBits > 0)
        {
            byte mask = (byte)(0xFF << (8 - remainingBits));
            if ((networkBytes[fullBytes] & mask) != (packetBytes[fullBytes] & mask))
                return false;
        }
        return true;
    }
    return ruleIP == packetIP;
}

static (string action, int ruleNumber, string description) EvaluatePacket(
    NetworkPacket packet, List<FirewallRule> rules)
{
    foreach (var rule in rules.OrderBy(r => r.RuleNumber))
    {
        bool sourceMatch = MatchesIP(rule.SourceIP, packet.SourceIP);
        bool destMatch = MatchesIP(rule.DestIP, packet.DestIP);
        bool protocolMatch = rule.Protocol == "any" ||
                             rule.Protocol == packet.Protocol;
        bool portMatch = rule.DestPort == -1 || rule.DestPort == packet.DestPort;

        if (sourceMatch && destMatch && protocolMatch && portMatch)
        {
            return (rule.Action, rule.RuleNumber, rule.Description);
        }
    }

    // Implicit deny (ultima regulă implicită)
    return ("DENY", 9999, "Implicit deny: nicio regulă nu s-a potrivit");
}

// Detectarea umbririi regulilor
static void DetectShadowing(List<FirewallRule> rules)
{
    Console.WriteLine("\n=== Analiza umbririi regulilor ===\n");
    var orderedRules = rules.OrderBy(r => r.RuleNumber).ToList();

    for (int i = 0; i < orderedRules.Count; i++)
    {
        for (int j = i + 1; j < orderedRules.Count; j++)
        {
            var earlier = orderedRules[i];
            var later = orderedRules[j];

            // Verificare simplificată: regula anterioară folosește "any"
            // și ascunde regulile ulterioare mai specifice
            bool sourceCovers = earlier.SourceIP == "any" ||
                                earlier.SourceIP == later.SourceIP;
            bool destCovers = earlier.DestIP == "any" ||
                              earlier.DestIP == later.DestIP;
            bool protocolCovers = earlier.Protocol == "any" ||
                                  earlier.Protocol == later.Protocol;
            bool portCovers = earlier.DestPort == -1 ||
                              earlier.DestPort == later.DestPort;

            if (sourceCovers && destCovers && protocolCovers && portCovers)
            {
                Console.WriteLine($"[!] Regula {later.RuleNumber} " +
                    $"(\"{later.Description}\") este ascunsă de regula " +
                    $"{earlier.RuleNumber} (\"{earlier.Description}\")");
                if (earlier.Action != later.Action)
                    Console.WriteLine($"  CRITIC: acțiunile diferă! " +
                        $"({earlier.Action} vs {later.Action})");
            }
        }
    }
}

// --- Declarațiile de tip stau DUPĂ instrucțiunile top-level (altfel CS8803) ---

// Simularea unui pachet de rețea
record NetworkPacket(
    string SourceIP,
    string DestIP,
    int SourcePort,
    int DestPort,
    string Protocol  // "TCP", "UDP", "ICMP"
);

// Regulă de firewall
record FirewallRule(
    int RuleNumber,
    string Action,          // "PERMIT" sau "DENY"
    string SourceIP,        // IP sau "any" sau CIDR (ex: "192.168.1.0/24")
    string DestIP,          // IP sau "any" sau CIDR
    string Protocol,        // "TCP", "UDP", "ICMP" sau "any"
    int DestPort,           // port sau -1 pentru "any"
    string Description
);
