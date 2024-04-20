namespace GlummysHookerKitchen;

public class TypeDatabaseConstants
{
    public static readonly Dictionary<string, string> GhidraTypeFriendlyTypeMap = new()
    {
        //TODO: Add more
        { "undefined", "bool" }, //1 byte type, can be many things, I personally expect a bool usually
        { "undefined2", "short" }, //2 bytes type
        { "undefined4", "int32_t" }, //4 bytes type
        { "undefined8", "int64_t" } //8 bytes type
    };

    public static readonly Dictionary<string, string> DoubleTypeDatabase = new()
    {
        //TODO: Add more
        { "longlong", "long long" },
        { "ulonglong", "unsigned long long" },
        { "uint", "unsigned int" },
        { "ushort", "unsigned short" },
    };
}