using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.Data.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
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
                    { "14990352-20f1-42da-af08-ed8c1d9aef98", "2", "User", "USER" },
                    { "1634fa1d-632a-49a3-8ef1-13c1e8ca1679", "3", "HR", "HR" },
                    { "78ea970a-3943-4343-bd7a-263ebdfadcc8", "1", "Admin", "ADMIN" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "14990352-20f1-42da-af08-ed8c1d9aef98");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1634fa1d-632a-49a3-8ef1-13c1e8ca1679");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "78ea970a-3943-4343-bd7a-263ebdfadcc8");

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
    }
}
