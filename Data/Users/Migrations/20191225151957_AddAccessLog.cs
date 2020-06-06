using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddAccessLog : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "accessLogs",
                columns: table => new
                {
                    AccessLogId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DateTime = table.Column<DateTime>(nullable: false),
                    Type = table.Column<string>(nullable: true),
                    HttpMethod = table.Column<string>(nullable: true),
                    StatusCode = table.Column<string>(nullable: true),
                    AbsoluteUrl = table.Column<string>(nullable: true),
                    Headers = table.Column<string>(nullable: true),
                    Body = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_accessLogs", x => x.AccessLogId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "accessLogs");
        }
    }
}
