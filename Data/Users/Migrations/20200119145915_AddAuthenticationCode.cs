using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddAuthenticationCode : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authenticationCodes",
                columns: table => new
                {
                    AuthenticationCodeId = table.Column<Guid>(nullable: false),
                    ExpiryDate = table.Column<DateTime>(nullable: false),
                    Value = table.Column<string>(nullable: true),
                    Active = table.Column<bool>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authenticationCodes", x => x.AuthenticationCodeId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authenticationCodes");
        }
    }
}
