using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MyScimApp.Data.Users.Migrations
{
    public partial class AddScimGroup : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "scimGroups",
                columns: table => new
                {
                    ScimGroupId = table.Column<string>(nullable: false),
                    ExternalId = table.Column<string>(nullable: true),
                    DisplayName = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimGroups", x => x.ScimGroupId);
                });

            migrationBuilder.CreateTable(
                name: "scimGroupMembers",
                columns: table => new
                {
                    ScimGroupMemberId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Value = table.Column<string>(nullable: true),
                    Reference = table.Column<string>(nullable: true),
                    Display = table.Column<string>(nullable: true),
                    ScimGroupId = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimGroupMembers", x => x.ScimGroupMemberId);
                    table.ForeignKey(
                        name: "FK_scimGroupMembers_scimGroups_ScimGroupId",
                        column: x => x.ScimGroupId,
                        principalTable: "scimGroups",
                        principalColumn: "ScimGroupId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scimGroupMetaDatas",
                columns: table => new
                {
                    ScimGroupMetaDataId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ResourceType = table.Column<string>(nullable: true),
                    Created = table.Column<DateTime>(nullable: false),
                    LastModified = table.Column<DateTime>(nullable: false),
                    Location = table.Column<string>(nullable: true),
                    Version = table.Column<string>(nullable: true),
                    ScimGroupId = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scimGroupMetaDatas", x => x.ScimGroupMetaDataId);
                    table.ForeignKey(
                        name: "FK_scimGroupMetaDatas_scimGroups_ScimGroupId",
                        column: x => x.ScimGroupId,
                        principalTable: "scimGroups",
                        principalColumn: "ScimGroupId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scimGroupMembers_ScimGroupId",
                table: "scimGroupMembers",
                column: "ScimGroupId");

            migrationBuilder.CreateIndex(
                name: "IX_scimGroupMetaDatas_ScimGroupId",
                table: "scimGroupMetaDatas",
                column: "ScimGroupId",
                unique: true,
                filter: "[ScimGroupId] IS NOT NULL");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scimGroupMembers");

            migrationBuilder.DropTable(
                name: "scimGroupMetaDatas");

            migrationBuilder.DropTable(
                name: "scimGroups");
        }
    }
}
