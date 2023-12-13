using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.Data.Migrations
{
    /// <inheritdoc />
    public partial class ChangedApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "46d6c896-c24c-4d17-b28f-84775bdd1cde");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5e1d24f7-66d0-4161-be42-66caf77deba6");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "df5a27cb-d0ac-4b92-928a-91a223fa260a");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1fab087e-a2b1-44e4-9397-2ea776b71def", "1", "Admin", "ADMIN" },
                    { "f78d9fd8-6f5f-42d7-8c3f-a56ce0a3f5ee", "3", "HR", "HR" },
                    { "fe3b64d2-ce6d-44ff-beec-7aa062c04679", "2", "User", "USER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1fab087e-a2b1-44e4-9397-2ea776b71def");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f78d9fd8-6f5f-42d7-8c3f-a56ce0a3f5ee");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "fe3b64d2-ce6d-44ff-beec-7aa062c04679");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "46d6c896-c24c-4d17-b28f-84775bdd1cde", "2", "User", "USER" },
                    { "5e1d24f7-66d0-4161-be42-66caf77deba6", "1", "Admin", "ADMIN" },
                    { "df5a27cb-d0ac-4b92-928a-91a223fa260a", "3", "HR", "HR" }
                });
        }
    }
}
