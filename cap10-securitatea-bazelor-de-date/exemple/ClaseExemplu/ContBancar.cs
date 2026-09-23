using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

public class ContBancar
{
    public int ContId { get; set; }
    public string Titular { get; set; } = "";
    public decimal Sold { get; set; }

    // Coloana rowversion, actualizată automat de SQL Server la fiecare UPDATE
    [Timestamp]
    public byte[] VersiuneRand { get; set; } = [];
}

public class BancaDbContext(DbContextOptions<BancaDbContext> options) : DbContext(options)
{
    public DbSet<ContBancar> ConturiBancare => Set<ContBancar>();
}

public static class ServiciuTransfer
{
    public static async Task<bool> RetrageAsync(BancaDbContext context, int contId, decimal suma)
    {
        try
        {
            var cont = await context.ConturiBancare.FindAsync(contId);
            if (cont is null || cont.Sold < suma)
                return false;

            cont.Sold -= suma;
            // UPDATE ... WHERE ContId = @id AND VersiuneRand = @versiuneCitita
            await context.SaveChangesAsync();
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            // Altcineva a modificat contul între citire și scriere:
            // reîncărcați datele și reîncercați sau raportați eroarea
            return false;
        }
    }
}
