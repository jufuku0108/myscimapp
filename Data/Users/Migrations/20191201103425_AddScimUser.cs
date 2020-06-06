using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddScimUser : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UserType",
                table: "AspNetUsers",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "scimUsers",
                columns: table => new
                {
                    ScimUserId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ExternalId = table.Column<string>(nullable: true),
                    UserName = table.Column<string>(nullable: true),
                    Active = table.Column<bool>(nullable: false),
                    DisplayName = table.Column<string>(nullable: true),
                    ApplicationUserId = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimUsers", x => x.ScimUserId);
                    table.ForeignKey(
                        name: "FK_scimUsers_AspNetUsers_ApplicationUserId",
                        column: x => x.ApplicationUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scimUserEmails",
                columns: table => new
                {
                    ScimUserEmailId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Primary = table.Column<bool>(nullable: false),
                    Type = table.Column<string>(nullable: true),
                    Value = table.Column<string>(nullable: true),
                    ScimUserId = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimUserEmails", x => x.ScimUserEmailId);
                    table.ForeignKey(
                        name: "FK_scimUserEmails_scimUsers_ScimUserId",
                        column: x => x.ScimUserId,
                        principalTable: "scimUsers",
                        principalColumn: "ScimUserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scimUserMetaDatas",
                columns: table => new
                {
                    ScimUserMetaDataId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ResourceType = table.Column<string>(nullable: true),
                    Created = table.Column<DateTime>(nullable: false),
                    LastModified = table.Column<DateTime>(nullable: false),
                    Location = table.Column<string>(nullable: true),
                    Version = table.Column<string>(nullable: true),
                    ScimUserId = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimUserMetaDatas", x => x.ScimUserMetaDataId);
                    table.ForeignKey(
                        name: "FK_scimUserMetaDatas_scimUsers_ScimUserId",
                        column: x => x.ScimUserId,
                        principalTable: "scimUsers",
                        principalColumn: "ScimUserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scimUserNames",
                columns: table => new
                {
                    ScimUserNameId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Formatted = table.Column<string>(nullable: true),
                    FamilyName = table.Column<string>(nullable: true),
                    GivenName = table.Column<string>(nullable: true),
                    ScimUserId = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimUserNames", x => x.ScimUserNameId);
                    table.ForeignKey(
                        name: "FK_scimUserNames_scimUsers_ScimUserId",
                        column: x => x.ScimUserId,
                        principalTable: "scimUsers",
                        principalColumn: "ScimUserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scimUserPhoneNumbers",
                columns: table => new
                {
                    ScimUserPhoneNumberId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Value = table.Column<string>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    ScimUserId = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimUserPhoneNumbers", x => x.ScimUserPhoneNumberId);
                    table.ForeignKey(
                        name: "FK_scimUserPhoneNumbers_scimUsers_ScimUserId",
                        column: x => x.ScimUserId,
                        principalTable: "scimUsers",
                        principalColumn: "ScimUserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scimUserEmails_ScimUserId",
                table: "scimUserEmails",
                column: "ScimUserId");

            migrationBuilder.CreateIndex(
                name: "IX_scimUserMetaDatas_ScimUserId",
                table: "scimUserMetaDatas",
                column: "ScimUserId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_scimUserNames_ScimUserId",
                table: "scimUserNames",
                column: "ScimUserId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_scimUserPhoneNumbers_ScimUserId",
                table: "scimUserPhoneNumbers",
                column: "ScimUserId");

            migrationBuilder.CreateIndex(
                name: "IX_scimUsers_ApplicationUserId",
                table: "scimUsers",
                column: "ApplicationUserId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scimUserEmails");

            migrationBuilder.DropTable(
                name: "scimUserMetaDatas");

            migrationBuilder.DropTable(
                name: "scimUserNames");

            migrationBuilder.DropTable(
                name: "scimUserPhoneNumbers");

            migrationBuilder.DropTable(
                name: "scimUsers");

            migrationBuilder.DropColumn(
                name: "UserType",
                table: "AspNetUsers");
        }
    }
}
