/*
 * Experimental, read-only FFDec library probe. Not registered as an MCP tool.
 * Prints JSON records; never calls export/save/decompile APIs.
 */
import java.io.*;
import java.util.*;
import com.jpexs.decompiler.flash.SWF;
import com.jpexs.decompiler.flash.abc.ABC;
import com.jpexs.decompiler.flash.abc.types.*;
import com.jpexs.decompiler.flash.abc.types.traits.*;
import com.jpexs.decompiler.flash.abc.avm2.instructions.*;

public class Avm2Probe {
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    static String name(ABC a, int index) {
        if (index == 0) return "*";
        return a.constants.getMultiname(index).toString(a.constants, Collections.emptyList());
    }
    static void own(Map<Integer,List<String>> owners, int method, String label) {
        owners.computeIfAbsent(method, k -> new ArrayList<>()).add(label);
    }
    static void traits(ABC a, Traits ts, String cls, Map<Integer,List<String>> owners) {
        for (Trait t : ts.traits) {
            if (t instanceof TraitMethodGetterSetter)
                own(owners, ((TraitMethodGetterSetter)t).method_info, cls + "::" + name(a,t.name_index));
        }
    }
    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless","true");
        SWF swf;
        try (InputStream in = new BufferedInputStream(new FileInputStream(args[0]))) {
            swf = new SWF(in, false);
        }
        int ai = 0;
        for (var tag : swf.getAbcList()) {
            ABC a = tag.getABC();
            Map<Integer,List<String>> owners = new HashMap<>();
            for (int ci=0;ci<a.instance_info.size();ci++) {
                InstanceInfo ii = a.instance_info.get(ci);
                ClassInfo cl = a.class_info.get(ci);
                String cn = name(a,ii.name_index);
                own(owners,ii.iinit_index,cn+"::<instance initializer>");
                own(owners,cl.cinit_index,cn+"::<static initializer>");
                traits(a,ii.instance_traits,cn,owners);
                traits(a,cl.static_traits,cn+" [static]",owners);
                System.out.println("{\"type\":\"class\",\"abc\":"+ai+",\"class_index\":"+ci
                    +",\"name\":"+q(cn)+",\"super\":"+q(name(a,ii.super_index))
                    +",\"iinit\":"+ii.iinit_index+",\"cinit\":"+cl.cinit_index
                    +",\"instance_traits\":"+ii.instance_traits.traits.size()+"}");
            }
            for (int si=0;si<a.script_info.size();si++) {
                ScriptInfo s = a.script_info.get(si);
                own(owners,s.init_index,"script"+si+"::<initializer>");
                traits(a,s.traits,"script"+si,owners);
            }
            for (MethodBody b : a.bodies) {
                List<String> labels = owners.getOrDefault(b.method_info,Collections.emptyList());
                String ownerJson = "["+String.join(",",labels.stream().map(Avm2Probe::q).toList())+"]";
                System.out.println("{\"type\":\"method\",\"abc\":"+ai+",\"method_id\":"+b.method_info
                    +",\"owners\":"+ownerJson+",\"max_stack\":"+b.max_stack
                    +",\"locals\":"+b.max_regs+",\"code_hex\":"+q(HexFormat.of().formatHex(b.getCodeBytes()))+"}");
                for (AVM2Instruction ins : b.getCode().code) {
                    String op = ins.definition.instructionName;
                    // Explicit op-name allowlist: don't mistake integer operands for multinames.
                    boolean property = Set.of("setproperty","initproperty","getproperty",
                        "deleteproperty","callproperty","callpropvoid","callsuper","callsupervoid",
                        "getsuper","setsuper","constructprop","getlex","findpropstrict","findproperty").contains(op);
                    Multiname mn = null;
                    int mi = 0;
                    if (property && ins.operands.length>0) {
                        mi = ins.operands[0]; mn = a.constants.getMultiname(mi);
                    }
                    String simple = mn != null && mn.name_index != 0
                        ? a.constants.getString(mn.name_index) : "";
                    System.out.println("{\"type\":\"instruction\",\"abc\":"+ai+",\"method_id\":"+b.method_info
                        +",\"owners\":"+ownerJson+",\"offset\":"+ins.getAddress()
                        +",\"opcode\":"+q(op)+",\"operands\":"+Arrays.toString(ins.operands)
                        +",\"multiname_id\":"+mi+",\"property\":"+q(simple)
                        +",\"multiname\":"+q(mn == null ? "" : name(a,mi))
                        +",\"runtime_name\":"+(mn != null && mn.needsName())
                        +",\"runtime_namespace\":"+(mn != null && mn.needsNs())+"}");
                }
            }
            ai++;
        }
        String documentClass = swf.getDocumentClass();
        if (documentClass != null && !documentClass.isEmpty())
            System.out.println("{\"type\":\"character\",\"id\":0,\"classes\":["+q(documentClass)
                +"],\"export_name\":\"\",\"dependencies\":[]}");
        for (var e : swf.getCharacters(false).entrySet()) {
            int id = e.getKey();
            String export = swf.getExportName(id);
            String classes = "["+String.join(",",e.getValue().getClassNames().stream().map(Avm2Probe::q).toList())+"]";
            System.out.println("{\"type\":\"character\",\"id\":"+id
                +",\"export_name\":"+q(export == null ? "" : export)
                +",\"classes\":"+classes
                +",\"dependencies\":"+swf.getDependentCharacters(id)+"}");
        }
    }
}
