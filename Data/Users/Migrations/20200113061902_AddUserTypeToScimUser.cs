using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddUserTypeToScimUser : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UserType",
                table: "scimUsers",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UserType",
                table: "scimUsers");
        }
    }
}
