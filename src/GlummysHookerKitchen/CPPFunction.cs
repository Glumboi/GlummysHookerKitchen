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
            Type = splitBySpace.First();

            foreach (var pair in TypeDatabaseConstants.GhidraTypeFriendlyTypeMap.Where(pair => Type == pair.Key))
            {
                Type = pair.Value;
            }
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
            foreach (var pair in TypeDatabaseConstants.GhidraTypeFriendlyTypeMap)
            {
                if (backPartSplitted.First() == pair.Key) return pair.Value;
            }

            return backPartSplitted.First();
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
            if (backPartSplitted.Length < 3)
            {
                return "__stdcall";
            }

            return backPartSplitted[^1]; //Calling convention should be between name and return type
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
        StringBuilder builder = new StringBuilder($"static {ReturnType} {Name}_hook(");
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
        builder.Append(
            $"\n{{\n\tDEBUG_TO_CONSOLE(\"{Name}\" << \" called!\\n\");\n\n\treturn {Name}_o({returnParametersBuilder.ToString()});\n}}");
        return builder.ToString();
    }

    public string GetFullHook()
    {
        return GetFunctionTypeDef() + "\n\n" + GetFunctionHook();
    }
}