/*
 * Read-only adapter to the installed FFDec library. No save/export APIs.
 * Requires Java 17+ source-file launcher and FFDec 26.4.0.
 */
import java.io.*;
import java.util.*;
import com.jpexs.decompiler.flash.SWF;
import com.jpexs.decompiler.flash.abc.ABC;
import com.jpexs.decompiler.flash.abc.AVM2LocalData;
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
    static String traitDetails(ABC abc, Traits traits) {
        StringJoiner result = new StringJoiner(",", "[", "]");
        for (Trait trait : traits.traits) {
            String slot = trait instanceof TraitWithSlot withSlot
                ? Integer.toString(withSlot.getSlotIndex()) : "null";
            result.add("{\"name\":" + q(name(abc, trait.name_index))
                + ",\"kind\":" + q(trait.getKindToStr())
                + ",\"declared_slot_id\":" + slot + "}");
        }
        return result.toString();
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
    static final Set<String> VALUE_PUSHES = Set.of(
        "pushnull", "pushundefined", "pushtrue", "pushfalse", "pushbyte",
        "pushshort", "pushint", "pushuint", "pushdouble", "pushstring", "pushnan");
    static final Set<String> VALUE_COERCIONS =
        Set.of("coerce", "coerce_a", "coerce_s", "convert_i", "convert_u", "convert_b");

    record SlotLayout(String resolution, String className, Map<Integer, Integer> slots) {}
    record ResolvedSlot(SlotLayout layout, int nameIndex, boolean unreachable) {}

    static SlotLayout slotLayout(String resolution, String className, Traits traits) {
        Map<Integer, Integer> slots = new HashMap<>();
        for (Trait trait : traits.traits) {
            if (!(trait instanceof TraitWithSlot slot)) continue;
            int id = slot.getSlotIndex();
            // An implicit or duplicate ID needs effective layout validation.
            if (id <= 0 || slots.putIfAbsent(id, trait.name_index) != null) return null;
        }
        return slots.isEmpty() ? null : new SlotLayout(resolution, className, slots);
    }

    static void addClassReceiver(Map<Integer, SlotLayout> receivers, Set<Integer> registered,
                                 int method, SlotLayout layout) {
        if (!registered.add(method)) receivers.remove(method);
        else if (layout != null) receivers.put(method, layout);
    }

    static Map<Integer, SlotLayout> classReceivers(ABC abc) {
        Map<Integer, SlotLayout> receivers = new HashMap<>();
        Set<Integer> registered = new HashSet<>();
        for (int i = 0; i < abc.class_info.size(); i++) {
            InstanceInfo instance = abc.instance_info.get(i);
            ClassInfo statics = abc.class_info.get(i);
            String owner = name(abc, instance.name_index);
            SlotLayout instanceLayout = slotLayout("instance_trait", owner, instance.instance_traits);
            SlotLayout staticLayout = slotLayout("static_trait", owner, statics.static_traits);
            addClassReceiver(receivers, registered, instance.iinit_index, instanceLayout);
            addClassReceiver(receivers, registered, statics.cinit_index, staticLayout);
            for (Trait trait : instance.instance_traits.traits)
                if (trait instanceof TraitMethodGetterSetter method)
                    addClassReceiver(receivers, registered, method.method_info, instanceLayout);
            for (Trait trait : statics.static_traits.traits)
                if (trait instanceof TraitMethodGetterSetter method)
                    addClassReceiver(receivers, registered, method.method_info, staticLayout);
        }
        for (ScriptInfo script : abc.script_info) {
            receivers.remove(script.init_index);
            for (Trait trait : script.traits.traits)
                if (trait instanceof TraitMethodGetterSetter method) receivers.remove(method.method_info);
        }
        Set<String> independentReceivers = Set.of("newfunction", "callstatic");
        for (MethodBody body : abc.bodies)
            for (AVM2Instruction ins : body.getCode().code)
                if (independentReceivers.contains(ins.definition.instructionName))
                    receivers.remove(ins.operands[0]);
        return receivers;
    }

    static int localIndex(AVM2Instruction ins, String op, String prefix) {
        if (op.equals(prefix)) return ins.operands[0];
        if (op.length() == prefix.length() + 1 && op.startsWith(prefix)) {
            int index = op.charAt(prefix.length()) - '0';
            if (index >= 0 && index <= 3) return index;
        }
        return -1;
    }

    // A null layout represents an unknown value. A null frame represents an
    // incoming path whose stack or scope shape could not be established.
    record Frame(Map<Integer, SlotLayout> locals, List<SlotLayout> stack, List<SlotLayout> scopes) {
        Frame copy() {
            return new Frame(new HashMap<>(locals), new ArrayList<>(stack), new ArrayList<>(scopes));
        }

        Frame merge(Frame other) {
            if (other == null || stack.size() != other.stack.size()
                    || scopes.size() != other.scopes.size()) return null;
            Frame merged = copy();
            merged.locals.entrySet().removeIf(e -> !Objects.equals(e.getValue(), other.locals.get(e.getKey())));
            for (int i = 0; i < stack.size(); i++)
                if (!Objects.equals(stack.get(i), other.stack.get(i))) merged.stack.set(i, null);
            for (int i = 0; i < scopes.size(); i++)
                if (!Objects.equals(scopes.get(i), other.scopes.get(i))) merged.scopes.set(i, null);
            return merged;
        }
    }

    static void enqueue(int index, Frame frame, Map<Integer, Frame> states, ArrayDeque<Integer> work) {
        boolean seen = states.containsKey(index);
        Frame previous = states.get(index);
        Frame merged = !seen ? frame : previous == null ? null : previous.merge(frame);
        if (!seen || !Objects.equals(previous, merged)) {
            states.put(index, merged);
            work.add(index);
        }
    }

    static final Set<String> STACK_ONLY = Set.of(
        "getslot", "newarray", "newobject", "constructsuper", "constructprop", "construct",
        "call", "callproperty", "callpropvoid", "callproplex", "callsuper", "callsupervoid",
        "getproperty", "setproperty", "initproperty", "findpropstrict", "findproperty", "getlex",
        "add", "add_i", "subtract", "subtract_i", "multiply", "multiply_i", "divide",
        "increment", "increment_i", "decrement", "decrement_i", "not", "equals", "strictequals",
        "lshift", "greaterequals", "greaterthan", "lessthan", "lessequals", "negate",
        "astypelate", "istypelate", "convert_d", "getglobalscope", "getdescendants",
        "bitor", "bitxor", "bitand", "rshift", "urshift", "checkfilter",
        "modulo", "nextname", "nextvalue", "hasnext2",
        "debug", "debugline", "debugfile", "label", "nop");

    static Frame transfer(AVM2Instruction ins, Frame frame, SlotLayout activation,
                          List<SlotLayout> catches, AVM2LocalData data) {
        Frame next = frame.copy();
        List<SlotLayout> stack = next.stack, scopes = next.scopes;
        String op = ins.definition.instructionName;
        int depth = stack.size();
        int load = localIndex(ins, op, "getlocal"), store = localIndex(ins, op, "setlocal");
        if (load >= 0) {
            stack.add(next.locals.get(load));
        } else if (op.equals("newcatch") && ins.operands[0] < catches.size()) {
            stack.add(catches.get(ins.operands[0]));
        } else if (op.equals("newactivation") || op.equals("newfunction") || VALUE_PUSHES.contains(op)) {
            stack.add(op.equals("newactivation") ? activation : null);
        } else if (op.equals("dup") && depth >= 1) {
            stack.add(stack.get(depth - 1));
        } else if (op.equals("swap") && depth >= 2) {
            Collections.swap(stack, depth - 1, depth - 2);
        } else if ((op.equals("pushscope") || op.equals("pushwith")) && depth >= 1) {
            scopes.add(stack.remove(depth - 1));
        } else if (op.equals("popscope") && !scopes.isEmpty()) {
            scopes.remove(scopes.size() - 1);
        } else if (op.equals("getscopeobject") && ins.operands[0] < scopes.size()) {
            stack.add(scopes.get(ins.operands[0]));
        } else if (store >= 0 && depth >= 1) {
            SlotLayout value = stack.remove(depth - 1);
            if (value == null) next.locals.remove(store);
            else next.locals.put(store, value);
        } else if (op.equals("kill") || op.startsWith("inclocal") || op.startsWith("declocal")) {
            next.locals.remove(ins.operands[0]);
        } else if (op.equals("pop") && depth >= 1) {
            stack.remove(depth - 1);
        } else if (VALUE_COERCIONS.contains(op) && depth >= 1) {
            stack.set(depth - 1, null);
        } else if (op.equals("setslot") && depth >= 2) {
            stack.subList(depth - 2, depth).clear();
        } else if (op.equals("jump") || ins.isBranch() || STACK_ONLY.contains(op)) {
            if (op.equals("hasnext2")) {
                // Enumeration updates both the object and index registers.
                next.locals.remove(ins.operands[0]);
                next.locals.remove(ins.operands[1]);
            }
            int pop = ins.getStackPopCount(data), push = ins.getStackPushCount(data);
            if (pop < 0 || pop > depth || push < 0 || depth - pop + push > data.methodBody.max_stack)
                return null;
            stack.subList(depth - pop, depth).clear();
            for (int i = 0; i < push; i++) stack.add(null);
        } else {
            return null;
        }
        if (stack.size() > data.methodBody.max_stack || scopes.size() > data.methodBody.max_scope_depth)
            return null;
        return next;
    }

    static Map<Long, ResolvedSlot> slotWrites(ABC abc, MethodBody body, SlotLayout classReceiver) {
        SlotLayout activation = slotLayout("activation_trait", null, body.traits);
        if (activation == null && classReceiver == null && body.exceptions.length == 0) return Map.of();
        List<AVM2Instruction> code = body.getCode().code;
        if (code.stream().noneMatch(ins -> ins.definition.instructionName.equals("setslot"))) return Map.of();

        Map<Long, Integer> positions = new HashMap<>();
        for (int i = 0; i < code.size(); i++) positions.put(code.get(i).getAddress(), i);
        Map<Integer, Frame> states = new HashMap<>();
        ArrayDeque<Integer> work = new ArrayDeque<>();
        Frame entry = new Frame(new HashMap<>(), new ArrayList<>(), new ArrayList<>());
        if (classReceiver != null) entry.locals.put(0, classReceiver);
        enqueue(0, entry, states, work);
        List<SlotLayout> catches = new ArrayList<>();
        for (ABCException handler : body.exceptions) {
            catches.add(handler.name_index == 0 ? null
                : new SlotLayout("catch_scope", null, Map.of(1, handler.name_index)));
        }
        AVM2LocalData data = new AVM2LocalData();
        data.abc = abc;
        data.methodBody = body;
        data.code = body.getCode();
        if (!traceSlots(code, positions, states, work, activation, catches, data)) return Map.of();

        Map<Long, ResolvedSlot> resolved = new HashMap<>();
        collectSlots(code, states, Collections.emptySet(), false, resolved);

        // Analyze empty-range handlers in isolation. Their synthetic entry
        // frames must never influence the method-entry analysis.
        Map<Integer, Frame> detached = new HashMap<>();
        for (ABCException handler : body.exceptions) {
            Integer target = positions.get((long) handler.target);
            if (handler.start == handler.end && target != null && !states.containsKey(target)) {
                Frame caught = new Frame(new HashMap<>(), new ArrayList<>(), new ArrayList<>());
                caught.stack.add(null);
                enqueue(target, caught, detached, work);
            }
        }
        if (traceSlots(code, positions, detached, work, null, catches, data))
            collectSlots(code, detached, states.keySet(), true, resolved);
        return resolved;
    }

    static boolean traceSlots(List<AVM2Instruction> code, Map<Long, Integer> positions,
                              Map<Integer, Frame> states, ArrayDeque<Integer> work,
                              SlotLayout activation, List<SlotLayout> catches, AVM2LocalData data) {
        long steps = 0, stepLimit = Math.min(100_000L, 32L * code.size());
        while (!work.isEmpty()) {
            if (++steps > stepLimit) return false;
            int i = work.remove();
            AVM2Instruction ins = code.get(i);
            String op = ins.definition.instructionName;
            Frame state = states.get(i);
            for (ABCException handler : data.methodBody.exceptions) {
                if (ins.getAddress() < handler.start || ins.getAddress() >= handler.end) continue;
                Integer target = positions.get((long) handler.target);
                if (target == null) continue;
                Frame caught = new Frame(state == null ? new HashMap<>() : new HashMap<>(state.locals),
                    new ArrayList<>(), new ArrayList<>());
                caught.stack.add(null);
                enqueue(target, caught, states, work);
            }
            if (ins.isExit() || op.equals("throw")) continue;
            Frame next = state == null ? null : transfer(ins, state, activation, catches, data);
            for (long target : ins.getOffsets()) {
                Integer index = positions.get(target);
                if (index != null) enqueue(index, next, states, work);
            }
            if (i + 1 < code.size() && !op.equals("jump") && !op.equals("lookupswitch"))
                enqueue(i + 1, next, states, work);
        }
        return true;
    }

    static void collectSlots(List<AVM2Instruction> code, Map<Integer, Frame> states,
                             Set<Integer> reachable, boolean unreachable, Map<Long, ResolvedSlot> resolved) {
        for (var entryState : states.entrySet()) {
            if (reachable.contains(entryState.getKey())) continue;
            AVM2Instruction ins = code.get(entryState.getKey());
            Frame state = entryState.getValue();
            if (state == null || !ins.definition.instructionName.equals("setslot") || state.stack.size() < 2)
                continue;
            SlotLayout receiver = state.stack.get(state.stack.size() - 2);
            if (receiver == null || unreachable && !receiver.resolution().equals("catch_scope")) continue;
            Integer nameIndex = receiver.slots().get(ins.operands[0]);
            if (nameIndex != null)
                resolved.put(ins.getAddress(), new ResolvedSlot(receiver, nameIndex, unreachable));
        }
    }
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
                        +",\"static_trait_count\":"+ci.static_traits.traits.size()
                        +",\"instance_traits\":"+traitDetails(a,ii.instance_traits)
                        +",\"static_traits\":"+traitDetails(a,ci.static_traits)+"}");
                }
                continue;
            }
            Map<Integer,Set<String>> direct=owners(a), all=enclosing(a,direct);
            boolean resolveWrites = op.equals("accesses") && !access.equals("read");
            Map<Integer, SlotLayout> receivers = resolveWrites ? classReceivers(a) : Map.of();
            for(MethodBody b:a.bodies) {
                if(op.equals("method") && b.method_info!=selectedMethod) continue;
                Map<Long, ResolvedSlot> resolvedSlots =
                    resolveWrites ? slotWrites(a,b,receivers.get(b.method_info)) : Map.of();
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
                    ResolvedSlot resolvedSlot = resolvedSlots.get(ins.getAddress());
                    if(MULTINAMES.contains(opcode)) {
                        mnIndex=ins.operands[0]; mn=a.constants.getMultiname(mnIndex);
                        if(mn.name_index!=0) simple=a.constants.getString(mn.name_index);
                    } else if (resolvedSlot != null) {
                        mnIndex=resolvedSlot.nameIndex(); mn=a.constants.getMultiname(mnIndex);
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
                        +",\"slot_id\":"+slot+",\"receiver_type\":"
                        +(resolvedSlot == null || resolvedSlot.layout().className() == null
                            ? "null" : q(resolvedSlot.layout().className()))
                        +(resolvedSlot == null ? "" : ",\"slot_resolution\":"+q(resolvedSlot.layout().resolution()))
                        +(resolvedSlot != null && resolvedSlot.unreachable() ? ",\"reachability\":\"unreachable\"" : "")+"}");
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
