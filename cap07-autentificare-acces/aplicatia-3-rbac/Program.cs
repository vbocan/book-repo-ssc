/// <summary>
/// Reprezintă o permisiune în sistemul RBAC.
/// </summary>
public record Permission(string Resource, string Action)
{
    public override string ToString() =>
        $"{Resource}:{Action}";
}

/// <summary>
/// Reprezintă un rol în sistemul RBAC, cu suport
/// pentru ierarhie (rol părinte).
/// </summary>
public class Role
{
    public string Name { get; }
    public Role? Parent { get; }
    private readonly HashSet<Permission> _permissions = new();

    public Role(string name, Role? parent = null)
    {
        Name = name;
        Parent = parent;
    }

    public void AddPermission(Permission permission) =>
        _permissions.Add(permission);

    /// <summary>
    /// Returnează permisiunile efective, incluzând cele
    /// moștenite de la rolul părinte (ierarhie RBAC).
    /// </summary>
    public IReadOnlySet<Permission> GetEffectivePermissions()
    {
        var effective = new HashSet<Permission>(_permissions);
        if (Parent != null)
        {
            foreach (var perm in
                     Parent.GetEffectivePermissions())
                effective.Add(perm);
        }
        return effective;
    }

    public override string ToString() =>
        Parent != null
            ? $"{Name} (moștenește de la {Parent.Name})"
            : Name;
}

/// <summary>
/// Implementare RBAC conform modelului NIST:
/// Core RBAC + Hierarchical RBAC + Static SoD.
/// </summary>
public class RbacSystem
{
    private readonly Dictionary<string, Role> _roles = new();
    private readonly Dictionary<string, HashSet<string>>
        _userRoles = new();

    // Constrângeri SSD: perechi de roluri mutual exclusive
    private readonly List<(string RoleA, string RoleB)>
        _ssdConstraints = new();

    // Sesiuni active: userId -> set de roluri activate
    private readonly Dictionary<string, HashSet<string>>
        _activeSessions = new();

    /// <summary>
    /// Definește un rol nou, opțional cu un rol părinte.
    /// </summary>
    public Role DefineRole(
        string name, string? parentRoleName = null)
    {
        Role? parent = parentRoleName != null
            ? _roles[parentRoleName]
            : null;
        var role = new Role(name, parent);
        _roles[name] = role;
        Console.WriteLine($"  Rol definit: {role}");
        return role;
    }

    /// <summary>
    /// Adaugă o permisiune la un rol.
    /// </summary>
    public void AddPermissionToRole(
        string roleName, Permission permission)
    {
        _roles[roleName].AddPermission(permission);
    }

    /// <summary>
    /// Definește o constrângere SSD: două roluri nu pot
    /// fi atribuite aceluiași utilizator.
    /// </summary>
    public void AddSsdConstraint(
        string roleA, string roleB)
    {
        _ssdConstraints.Add((roleA, roleB));
        Console.WriteLine(
            $"  Constrângere SSD: {roleA} ↔ {roleB} " +
            $"(mutual exclusive)");
    }

    /// <summary>
    /// Atribuie un rol unui utilizator, verificând
    /// constrângerile SSD.
    /// </summary>
    public bool AssignRoleToUser(
        string userId, string roleName)
    {
        if (!_roles.ContainsKey(roleName))
        {
            Console.WriteLine(
                $"  EROARE: Rolul '{roleName}' nu există.");
            return false;
        }

        if (!_userRoles.ContainsKey(userId))
            _userRoles[userId] = new HashSet<string>();

        // Verificare constrângeri SSD
        foreach (var (roleA, roleB) in _ssdConstraints)
        {
            if (roleName == roleA &&
                _userRoles[userId].Contains(roleB))
            {
                Console.WriteLine(
                    $"  REFUZAT: Utilizatorul '{userId}' " +
                    $"are deja rolul '{roleB}', " +
                    $"incompatibil cu '{roleA}' (SSD).");
                return false;
            }
            if (roleName == roleB &&
                _userRoles[userId].Contains(roleA))
            {
                Console.WriteLine(
                    $"  REFUZAT: Utilizatorul '{userId}' " +
                    $"are deja rolul '{roleA}', " +
                    $"incompatibil cu '{roleB}' (SSD).");
                return false;
            }
        }

        _userRoles[userId].Add(roleName);
        Console.WriteLine(
            $"  Utilizator '{userId}' -> rol '{roleName}'");
        return true;
    }

    /// <summary>
    /// Creează o sesiune, activând un subset de roluri
    /// ale utilizatorului.
    /// </summary>
    public bool CreateSession(
        string userId, IEnumerable<string> rolesToActivate)
    {
        if (!_userRoles.ContainsKey(userId))
        {
            Console.WriteLine(
                $"  EROARE: Utilizatorul '{userId}' " +
                $"nu există.");
            return false;
        }

        var roles = rolesToActivate.ToHashSet();

        // Verifică că utilizatorul are rolurile solicitate
        foreach (string role in roles)
        {
            if (!_userRoles[userId].Contains(role))
            {
                Console.WriteLine(
                    $"  EROARE: '{userId}' nu are " +
                    $"rolul '{role}'.");
                return false;
            }
        }

        _activeSessions[userId] = roles;
        Console.WriteLine(
            $"  Sesiune creată: '{userId}' cu rolurile " +
            $"[{string.Join(", ", roles)}]");
        return true;
    }

    /// <summary>
    /// Verifică dacă un utilizator (în sesiunea curentă)
    /// are o anumită permisiune.
    /// </summary>
    public bool CheckAccess(
        string userId, Permission permission)
    {
        if (!_activeSessions.TryGetValue(
                userId, out var activeRoles))
        {
            Console.WriteLine(
                $"  Acces REFUZAT: '{userId}' " +
                $"nu are sesiune activă.");
            return false;
        }

        // Colectează permisiunile efective din toate
        // rolurile activate (inclusiv moștenite)
        foreach (string roleName in activeRoles)
        {
            var effectivePerms =
                _roles[roleName].GetEffectivePermissions();
            if (effectivePerms.Contains(permission))
            {
                Console.WriteLine(
                    $"  Acces PERMIS: '{userId}' -> " +
                    $"{permission} (prin rolul '{roleName}')");
                return true;
            }
        }

        Console.WriteLine(
            $"  Acces REFUZAT: '{userId}' -> " +
            $"{permission}");
        return false;
    }

    /// <summary>
    /// Afișează toate permisiunile efective ale
    /// unui utilizator.
    /// </summary>
    public void ShowUserPermissions(string userId)
    {
        if (!_userRoles.ContainsKey(userId))
        {
            Console.WriteLine(
                $"  Utilizatorul '{userId}' nu există.");
            return;
        }

        Console.WriteLine(
            $"\n  Permisiuni pentru '{userId}':");
        Console.WriteLine(
            $"  Roluri atribuite: " +
            $"[{string.Join(", ", _userRoles[userId])}]");

        var allPermissions = new HashSet<Permission>();
        foreach (string roleName in _userRoles[userId])
        {
            var perms =
                _roles[roleName].GetEffectivePermissions();
            foreach (var p in perms)
                allPermissions.Add(p);
        }

        Console.WriteLine("  Permisiuni efective:");
        foreach (var perm in
                 allPermissions.OrderBy(p => p.ToString()))
        {
            Console.WriteLine($"    - {perm}");
        }
    }
}

// --- Utilizare ---
class Program
{
    static void Main()
    {
        var rbac = new RbacSystem();

        // Definirea ierarhiei de roluri
        Console.WriteLine("=== Definire roluri ===");
        rbac.DefineRole("Angajat");
        rbac.DefineRole("Dezvoltator", "Angajat");
        rbac.DefineRole("TeamLead", "Dezvoltator");
        rbac.DefineRole("Contabil", "Angajat");
        rbac.DefineRole("Auditor", "Angajat");
        rbac.DefineRole("Admin");

        // Definirea permisiunilor
        Console.WriteLine("\n=== Definire permisiuni ===");
        // Angajat: operațiuni de bază
        rbac.AddPermissionToRole("Angajat",
            new Permission("Profil", "Citire"));
        rbac.AddPermissionToRole("Angajat",
            new Permission("Profil", "Editare"));
        rbac.AddPermissionToRole("Angajat",
            new Permission("Documente", "Citire"));

        // Dezvoltator: + acces la cod
        rbac.AddPermissionToRole("Dezvoltator",
            new Permission("Repository", "Citire"));
        rbac.AddPermissionToRole("Dezvoltator",
            new Permission("Repository", "Scriere"));
        rbac.AddPermissionToRole("Dezvoltator",
            new Permission("Pipeline", "Execuție"));

        // TeamLead: + gestiune echipă
        rbac.AddPermissionToRole("TeamLead",
            new Permission("Echipă", "Gestionare"));
        rbac.AddPermissionToRole("TeamLead",
            new Permission("Repository", "Aprobare"));

        // Contabil: operațiuni financiare
        rbac.AddPermissionToRole("Contabil",
            new Permission("Financiar", "Citire"));
        rbac.AddPermissionToRole("Contabil",
            new Permission("Financiar", "Scriere"));
        rbac.AddPermissionToRole("Contabil",
            new Permission("Facturi", "Emitere"));

        // Auditor: doar citire financiară
        rbac.AddPermissionToRole("Auditor",
            new Permission("Financiar", "Citire"));
        rbac.AddPermissionToRole("Auditor",
            new Permission("Audit", "Raportare"));

        // Admin: operațiuni de sistem
        rbac.AddPermissionToRole("Admin",
            new Permission("Sistem", "Configurare"));
        rbac.AddPermissionToRole("Admin",
            new Permission("Utilizatori", "Gestionare"));

        Console.WriteLine("Permisiuni definite.");

        // Constrângeri SSD (separarea responsabilităților)
        Console.WriteLine(
            "\n=== Constrângeri SSD ===");
        rbac.AddSsdConstraint("Contabil", "Auditor");

        // Atribuire roluri utilizatorilor
        Console.WriteLine(
            "\n=== Atribuire roluri ===");
        rbac.AssignRoleToUser("ioana", "TeamLead");
        rbac.AssignRoleToUser("mihai", "Dezvoltator");
        rbac.AssignRoleToUser("elena", "Contabil");
        rbac.AssignRoleToUser("elena", "Admin");

        // Încercare de încălcare a SSD
        rbac.AssignRoleToUser("elena", "Auditor");

        // Afișare permisiuni
        rbac.ShowUserPermissions("ioana");
        rbac.ShowUserPermissions("elena");

        // Crearea sesiunilor și verificarea accesului
        Console.WriteLine(
            "\n=== Verificare acces ===");
        rbac.CreateSession(
            "ioana", new[] { "TeamLead" });
        rbac.CreateSession(
            "mihai", new[] { "Dezvoltator" });
        rbac.CreateSession(
            "elena", new[] { "Contabil" });

        // TeamLead poate aproba cod (permisiune directă)
        rbac.CheckAccess("ioana",
            new Permission("Repository", "Aprobare"));

        // TeamLead poate citi documente
        // (moștenire: TeamLead -> Dezvoltator -> Angajat)
        rbac.CheckAccess("ioana",
            new Permission("Documente", "Citire"));

        // Dezvoltator nu poate gestiona echipa
        rbac.CheckAccess("mihai",
            new Permission("Echipă", "Gestionare"));

        // Contabil poate emite facturi
        rbac.CheckAccess("elena",
            new Permission("Facturi", "Emitere"));

        // Contabil nu poate accesa repository-ul
        rbac.CheckAccess("elena",
            new Permission("Repository", "Citire"));
    }
}
