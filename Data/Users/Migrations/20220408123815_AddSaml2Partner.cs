using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddSaml2Partner : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Saml2Partner",
                columns: table => new
                {
                    Saml2PartnerId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Issuer = table.Column<string>(nullable: true),
                    MetadataUrl = table.Column<string>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    RegisteredBy = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Saml2Partner", x => x.Saml2PartnerId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Saml2Partner");
        }
    }
}
