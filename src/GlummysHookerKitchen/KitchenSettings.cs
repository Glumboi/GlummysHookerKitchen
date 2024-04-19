using TinyINIController;

namespace GlummysHookerKitchen;

public struct KitchenSettings
{
    private IniFile backingIni;

    public IniFile BackingIni
    {
        get => backingIni;
        private set => backingIni = value;
    }

    private string ghidraPath;

    public string GhidraPath
    {
        get => ghidraPath;
        set
        {
            ghidraPath = value;
            backingIni.Write("ghidraPath", value, "Config");
        }
    }

    public KitchenSettings(string iniLoc)
    {
        backingIni = new IniFile(iniLoc);

        //Standard ini values
        if (!backingIni.KeyExists("ghidraPath", "Config"))
        {
            backingIni.Write("ghidraPath", "UNDEFINED", "Config");
        }

        ghidraPath = backingIni.Read("ghidraPath", "Config");
    }
}