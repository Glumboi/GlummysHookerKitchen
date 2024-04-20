using System.Text;

namespace GlummysHookerKitchen;

public class CPPParamter
{
    private string name = "";

    public string Name
    {
        get => name;
        set => name = value;
    }

    private string type = "";

    public string Type
    {
        get => type;
        set => type = value;
    }

    public CPPParamter(string param)
    {
        if (param.IndexOf(' ') != -1)
        {
            var splitBySpace = param.Split(' ');
            Name = splitBySpace.Last();

            /* int spaceCount = splitBySpace.Length - 1;
             if (spaceCount >
                 1) //Allow double types like long long when they are defined with a space between (didnt test this)
             {
                 int indexOfNameStart = Name.IndexOf(Name.First());
                 Type = param.Substring(0, param.Length - indexOfNameStart - 1);
             }*/
            /*else
            {*/
            string tempType = splitBySpace.First();
            string tempTypeNoPtr = tempType.Replace("*", "").Replace("&", "");

            int len = TypeDatabaseConstants.GhidraTypeFriendlyTypeMap.Count;
            for (int i = 0; i < len; i++)
            {
                KeyValuePair<string, string> pair =
                    TypeDatabaseConstants.GhidraTypeFriendlyTypeMap.ElementAt(i);
                if (tempTypeNoPtr == pair.Key)
                    tempType = tempType.Replace(pair.Key, pair.Value);
            }

            for (int j = 0; j < TypeDatabaseConstants.DoubleTypeDatabase.Count; j++)
            {
                KeyValuePair<string, string> pair2 =
                    TypeDatabaseConstants.DoubleTypeDatabase.ElementAt(j);
                if (tempTypeNoPtr == pair2.Key)
                    tempType = tempType.Replace(pair2.Key, pair2.Value);
            }

            Type = tempType;
            //}
        }

        //Do nothing if parameter only consists of void, so we have clean code
    }

    public override string ToString() => Type == string.Empty ? "" : Type + ' ' + Name;
}

public class CPPFunction
{
    private string backPart;
    private string[] backPartSplitted;

    public string BackPart //return type and calling convention combined with name
    {
        get => backPart;
        set
        {
            backPart = value;
            backPartSplitted = value.Split(' ');
        }
    }

    public string ReturnType
    {
        get
        {
            int len = TypeDatabaseConstants.GhidraTypeFriendlyTypeMap.Count;
            string tempType = backPartSplitted.First();
            string tempTypeNoPtr = tempType.Replace("*", "").Replace("&", "");


            for (int i = 0; i < len; i++)
            {
                KeyValuePair<string, string> pair =
                    TypeDatabaseConstants.GhidraTypeFriendlyTypeMap.ElementAt(i);
                if (tempTypeNoPtr == pair.Key)
                    tempType = tempType.Replace(pair.Key, pair.Value);
            }

            for (int j = 0; j < TypeDatabaseConstants.DoubleTypeDatabase.Count; j++)
            {
                KeyValuePair<string, string> pair2 =
                    TypeDatabaseConstants.DoubleTypeDatabase.ElementAt(j);
                if (tempTypeNoPtr == pair2.Key)
                    tempType = tempType.Replace(pair2.Key, pair2.Value);
            }

            return tempType;
        }
    }

    private List<CPPParamter> parameters = new();

    public List<CPPParamter> Parameters
    {
        get => parameters;
        set => parameters = value;
    }

    public string CallingConvention
    {
        get
        {
            return "__stdcall"; //Only __stdcall for now due to some issues with undefined calling conventions 
            /*if (backPartSplitted.Length < 3)
            {
            }

            return backPartSplitted[^1]; //Calling convention should be between name and return type*/
        }
    }

    public string Name
    {
        get => backPartSplitted.Last(); //Should always return the name since its the last part
    }

    public CPPFunction(string sig)
    {
        int firstBracketIndex = sig.IndexOf('(');
        int lastBracketIndex = sig.IndexOf(')');
        BackPart = sig.Substring(0, firstBracketIndex);
        string paramters = sig.Substring(firstBracketIndex + 1, lastBracketIndex - firstBracketIndex - 1);
        string[] paramsSeperated = paramters.Split(",");
        CPPParamter currentParamter = null;

        foreach (var parameter in paramsSeperated)
        {
            if (parameter.Contains('*') || parameter.Contains('&'))
            {
                //Space gets removed below so setting the index to it will cause it to actually point to the pointer/ref declaration
                int specialCharIndex = parameter.IndexOf(' ');
                string trimmed = parameter.Replace(" ", "");
                currentParamter = new CPPParamter(trimmed.Insert(specialCharIndex + 1, " "));
                Parameters.Add(currentParamter);
                continue;
            }

            currentParamter = new CPPParamter(parameter);
            Parameters.Add(currentParamter);
        }
    }

    public void PrintInfo()
    {
        Console.WriteLine("Backpart: " + BackPart);
        Console.WriteLine("Hook:\n");
        Console.WriteLine(GetFullHook());
        Console.Write('\n');
        /*Console.WriteLine("Function typedef:\n" + GetFunctionTypeDef());
        Console.WriteLine("Function hook:\n" + GetFunctionHook());*/
    }

    private string GetFunctionTypeDef()
    {
        StringBuilder builder = new StringBuilder($"using {Name}_t = {ReturnType}({CallingConvention}*)(");

        for (var i = 0; i < Parameters.Count; i++)
        {
            var parameter = Parameters[i];
            if (Parameters.Last() != parameter)
            {
                builder.Append(parameter.Type + ", ");
                continue;
            }

            builder.Append(parameter.Type);
        }

        builder.Append(");");
        builder.Append($"\nstatic {Name}_t {Name}_o;");
        return builder.ToString();
    }

    private string GetFunctionHook()
    {
        StringBuilder builder = new StringBuilder($"{ReturnType} {Name}(");
        for (var i = 0; i < Parameters.Count; i++)
        {
            var parameter = Parameters[i];
            if (Parameters.Last() != parameter)
            {
                builder.Append(parameter + ", ");
                continue;
            }

            builder.Append(parameter);
        }

        StringBuilder returnParametersBuilder = new StringBuilder();
        for (var i = 0; i < Parameters.Count; i++)
        {
            var parameter = Parameters[i];
            if (Parameters.Last() != parameter)
            {
                returnParametersBuilder.Append(parameter.Name + ", ");
                continue;
            }

            returnParametersBuilder.Append(parameter.Name);
        }

        builder.Append(')');

        StringBuilder printMsgBuilder =
            new StringBuilder($"\n\tTOPSEPERATOR << \"{Name}\" << \" called!\\n\"");
        foreach (var parameter in Parameters)
        {
            if (parameter.Type != string.Empty)
                printMsgBuilder.Append($"\n\t<< \"{parameter.Name}: \" << {parameter.Name} << \"\\n\"");
        }

        builder.Append(
            $"\n{{\n\tDEBUG_TO_CONSOLE({printMsgBuilder});\n\n\treturn {Name}_o({returnParametersBuilder.ToString()});\n}}");
        return builder.ToString();
    }

    public string GetFullHook()
    {
        return GetFunctionTypeDef() + "\n\n" + GetFunctionHook() + "\n\n";
    }
}