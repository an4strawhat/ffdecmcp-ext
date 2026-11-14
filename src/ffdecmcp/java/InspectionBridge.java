/*
 * Read-only adapter to the installed FFDec library. No save/export APIs.
 * Requires Java 17+ source-file launcher and FFDec 26.4.0.
 */
import java.io.*;
import java.util.*;
import com.jpexs.decompiler.flash.SWF;
import com.jpexs.decompiler.flash.abc.ABC;
import com.jpexs.decompiler.flash.abc.types.*;
import com.jpexs.decompiler.flash.abc.types.traits.*;
import com.jpexs.decompiler.flash.abc.avm2.instructions.*;

public class InspectionBridge {
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 32 || c > 126) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    static String array(Collection<String> ss) {
        return "["+String.join(",",ss.stream().map(InspectionBridge::q).toList())+"]";
    }
    static String name(ABC a, int index) {
        return index == 0 ? "*" : a.constants.getMultiname(index).toString(a.constants,Collections.emptyList());
    }
    static void own(Map<Integer,Set<String>> map, int id, String label) {
        map.computeIfAbsent(id,k->new TreeSet<>()).add(label);
    }
    static void traits(ABC a, Traits ts, String owner, Map<Integer,Set<String>> map) {
        for (Trait t : ts.traits)
            if (t instanceof TraitMethodGetterSetter)
                own(map,((TraitMethodGetterSetter)t).method_info,owner+"::"+name(a,t.name_index));
    }
    static Map<Integer,Set<String>> owners(ABC a) {
        Map<Integer,Set<String>> result = new HashMap<>();
        for (int i=0;i<a.instance_info.size();i++) {
            InstanceInfo ii=a.instance_info.get(i);
            ClassInfo ci=a.class_info.get(i);
            String cn=name(a,ii.name_index);
            own(result,ii.iinit_index,cn+"::<instance initializer>");
            own(result,ci.cinit_index,cn+"::<static initializer>");
            traits(a,ii.instance_traits,cn,result);
            traits(a,ci.static_traits,cn+" [static]",result);
        }
        for (int i=0;i<a.script_info.size();i++) {
            ScriptInfo si=a.script_info.get(i);
            own(result,si.init_index,"script"+i+"::<initializer>");
            traits(a,si.traits,"script"+i,result);
        }
        return result;
    }
    static Map<Integer,Set<String>> enclosing(ABC a, Map<Integer,Set<String>> direct) {
        Map<Integer,Set<String>> all=new HashMap<>();
        direct.forEach((k,v)->all.put(k,new TreeSet<>(v)));
        Map<Integer,Set<Integer>> edges=new HashMap<>();
        for (MethodBody b:a.bodies)
            for (AVM2Instruction ins:b.getCode().code)
                if (ins.definition.instructionName.equals("newfunction"))
                    edges.computeIfAbsent(b.method_info,k->new TreeSet<>()).add(ins.operands[0]);
        ArrayDeque<Integer> queue=new ArrayDeque<>(all.keySet());
        while(!queue.isEmpty()) {
            int parent=queue.removeFirst();
            for(int child:edges.getOrDefault(parent,Collections.emptySet())) {
                if(all.computeIfAbsent(child,k->new TreeSet<>()).addAll(all.get(parent)))
                    queue.addLast(child);
            }
        }
        return all;
    }
    static String context(int id,Map<Integer,Set<String>> direct,Map<Integer,Set<String>> all) {
        Set<String> d=direct.getOrDefault(id,Collections.emptySet());
        Set<String> c=all.getOrDefault(id,Collections.emptySet());
        return "\"direct_owners\":"+array(d)+",\"enclosing_contexts\":"+array(c)
            +",\"ownership\":"+q(!d.isEmpty()?"direct":!c.isEmpty()?"lexical_context":"unresolved");
    }
    static int offset, limit, budget, total=0, used=0;
    static boolean full=false;
    static List<String> rows=new ArrayList<>();
    static void emit(String row) {
        int index=total++;
        if(index<offset || full) return;
        // ASCII serialization: Java character count equals UTF-8 byte count.
        if(rows.size()>=limit || used+row.length()+1>budget-2048) {
            if(rows.isEmpty()) throw new IllegalArgumentException("One result exceeds max_bytes; narrow the query");
            full=true;
            return;
        }
        rows.add(row); used+=row.length()+1;
    }
    static final Set<String> WRITES=Set.of("setproperty","initproperty","setsuper","setslot","setglobalslot");
    static final Set<String> READS=Set.of("getproperty","getsuper","getslot","getglobalslot");
    static final Set<String> MULTINAMES=Set.of("setproperty","initproperty","setsuper","getproperty","getsuper");
    static void run(String[] args) throws Exception {
        String op=args[0], property=args[4], access=args[5];
        int selectedAbc=Integer.parseInt(args[2]), selectedMethod=Integer.parseInt(args[3]);
        offset=Integer.parseInt(args[6]); limit=Integer.parseInt(args[7]); budget=Integer.parseInt(args[8]);
        SWF swf;
        try(InputStream in=new BufferedInputStream(new FileInputStream(args[1]))) { swf=new SWF(in,false); }
        boolean foundMethod=false, foundAbc=false;
        int ai=0;
        for(var tag:swf.getAbcList()) {
            ABC a=tag.getABC();
            int abc=ai++;
            if(selectedAbc>=0 && selectedAbc!=abc) continue;
            foundAbc=true;
            if(op.equals("classes")) {
                for(int i=0;i<a.instance_info.size();i++) {
                    InstanceInfo ii=a.instance_info.get(i); ClassInfo ci=a.class_info.get(i);
                    List<String> interfaces=new ArrayList<>();
                    for(int index:ii.interfaces) interfaces.add(name(a,index));
                    emit("{\"abc_index\":"+abc+",\"class_index\":"+i+",\"name\":"+q(name(a,ii.name_index))
                        +",\"superclass\":"+q(name(a,ii.super_index))+",\"interfaces\":"+array(interfaces)
                        +",\"instance_initializer\":"+ii.iinit_index+",\"static_initializer\":"+ci.cinit_index
                        +",\"instance_trait_count\":"+ii.instance_traits.traits.size()
                        +",\"static_trait_count\":"+ci.static_traits.traits.size()+"}");
                }
                continue;
            }
            Map<Integer,Set<String>> direct=owners(a), all=enclosing(a,direct);
            for(MethodBody b:a.bodies) {
                if(op.equals("method") && b.method_info!=selectedMethod) continue;
                if(op.equals("method")) {
                    foundMethod=true;
                    MethodInfo mi=a.method_info.get(b.method_info);
                    List<String> params=new ArrayList<>();
                    for(int index:mi.param_types) params.add(name(a,index));
                    List<String> exceptions=new ArrayList<>();
                    for(ABCException e:b.exceptions)
                        exceptions.add("{\"start\":"+e.start+",\"end\":"+e.end+",\"target\":"+e.target
                            +",\"type\":"+q(name(a,e.type_index))+"}");
                    emit("{\"kind\":\"method\",\"abc_index\":"+abc+",\"method_id\":"+b.method_info
                        +","+context(b.method_info,direct,all)+",\"parameter_types\":"+array(params)
                        +",\"return_type\":"+q(name(a,mi.ret_type))+",\"flags\":"+mi.flags
                        +",\"max_stack\":"+b.max_stack+",\"local_count\":"+b.max_regs
                        +",\"init_scope_depth\":"+b.init_scope_depth+",\"max_scope_depth\":"+b.max_scope_depth
                        +",\"exceptions\":["+String.join(",",exceptions)+"]}");
                }
                for(AVM2Instruction ins:b.getCode().code) {
                    String opcode=ins.definition.instructionName;
                    boolean read=READS.contains(opcode), write=WRITES.contains(opcode);
                    int mnIndex=0; Multiname mn=null; String simple="";
                    if(MULTINAMES.contains(opcode)) {
                        mnIndex=ins.operands[0]; mn=a.constants.getMultiname(mnIndex);
                        if(mn.name_index!=0) simple=a.constants.getString(mn.name_index);
                    }
                    if(op.equals("accesses")) {
                        if(!(read||write)) continue;
                        if(access.equals("write")&&!write || access.equals("read")&&!read) continue;
                        if(!property.isEmpty()&&!simple.equals(property)) continue;
                    }
                    String slot=opcode.contains("slot")&&ins.operands.length>0?""+ins.operands[0]:"null";
                    emit("{\"kind\":\"instruction\",\"abc_index\":"+abc+",\"method_id\":"+b.method_info
                        +","+context(b.method_info,direct,all)+",\"offset\":"+ins.getAddress()
                        +",\"opcode\":"+q(opcode)+",\"operands\":"+Arrays.toString(ins.operands)
                        +",\"property_name\":"+q(simple)+",\"multiname_index\":"+mnIndex
                        +",\"multiname\":"+q(mn==null?"":name(a,mnIndex))
                        +",\"runtime_name\":"+(mn!=null&&mn.needsName())
                        +",\"runtime_namespace\":"+(mn!=null&&mn.needsNs())
                        +",\"slot_id\":"+slot+",\"receiver_type\":null}");
                }
            }
        }
        if(selectedAbc>=0&&!foundAbc) throw new IllegalArgumentException("ABC index not found");
        if(op.equals("method")&&!foundMethod) throw new IllegalArgumentException("Method body not found");
        if(offset>total) throw new IllegalArgumentException("Offset exceeds result count");
        String next=offset+rows.size()<total?""+(offset+rows.size()):"null";
        System.out.println("{\"bridge_version\":1,\"results\":["+String.join(",",rows)
            +"],\"total\":"+total+",\"next_offset\":"+next+"}");
    }
    public static void main(String[] args) {
        try { run(args); }
        catch(Throwable e) {
            System.err.println(e.getClass().getSimpleName()+": "+e.getMessage());
            System.exit(2);
        }
    }
}
