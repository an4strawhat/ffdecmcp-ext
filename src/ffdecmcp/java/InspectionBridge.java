/*
 * Read-only adapter to the installed FFDec library. No save/export APIs.
 * Requires the Java 17+ source-file launcher and FFDec 26.4.0 or 26.5.0.
 */
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import com.jpexs.decompiler.flash.SWF;
import com.jpexs.decompiler.flash.ReadOnlyTagList;
import com.jpexs.decompiler.flash.tags.*;
import com.jpexs.decompiler.flash.tags.base.PlaceObjectTypeTag;
import com.jpexs.decompiler.flash.abc.ABC;
import com.jpexs.decompiler.flash.abc.AVM2LocalData;
import com.jpexs.decompiler.flash.abc.avm2.AVM2Code;
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
    static Map<Integer,Set<String>> classOwners(ABC a) {
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
        return result;
    }
    static Map<Integer,Set<String>> owners(ABC a) {
        Map<Integer,Set<String>> result = classOwners(a);
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
    record LinkageFilter(String kind, int characterId, String timeline) {
        boolean matches(String rowKind, int id) {
            return (kind.equals("all") || kind.equals(rowKind))
                && (characterId < 0 || characterId == id);
        }
    }

    static void linkageNames(LinkageFilter filter, String kind, List<Integer> ids,
                             List<String> names, List<Integer> path, int tagIndex) {
        for (int i = 0; i < ids.size(); i++) {
            int id = ids.get(i);
            if (filter.matches(kind, id)) {
                emit("{\"kind\":" + q(kind) + ",\"character_id\":" + id
                    + ",\"name\":" + q(names.get(i)) + ",\"timeline_path\":" + path
                    + ",\"tag_index\":" + tagIndex + ",\"entry_index\":" + i + "}");
            }
        }
    }

    static String nullableString(String value) {
        return value == null ? "null" : q(value);
    }

    static void linkage(ReadOnlyTagList tags, List<Integer> path, LinkageFilter filter) {
        boolean root = path.isEmpty();
        boolean include = filter.timeline().equals("all")
            || filter.timeline().equals(root ? "root" : "nested");
        int frame = 1, nextTagIndex = 0;
        for (Tag tag : tags) {
            int tagIndex = nextTagIndex++;
            if (tag instanceof DefineSpriteTag sprite && !filter.timeline().equals("root")) {
                path.add(sprite.getCharacterId());
                linkage(sprite.getTags(), path, filter);
                path.remove(path.size() - 1);
            }
            if (!include) continue;
            if (tag instanceof ShowFrameTag) {
                frame++;
            } else if (tag instanceof SymbolClassTag symbols) {
                linkageNames(filter, "symbol_class", symbols.tags, symbols.names, path, tagIndex);
            } else if (tag instanceof ExportAssetsTag exports) {
                linkageNames(filter, "export_asset", exports.tags, exports.names, path, tagIndex);
            } else if (tag instanceof PlaceObjectTypeTag place) {
                int id = place.getCharacterId();
                if (!filter.matches("placement", id)) continue;
                emit("{\"kind\":\"placement\",\"character_id\":" + (id < 0 ? "null" : id)
                    + ",\"class_name\":" + nullableString(place.getClassName())
                    + ",\"instance_name\":" + nullableString(place.getInstanceName())
                    + ",\"timeline_path\":" + path + ",\"frame\":" + frame
                    + ",\"tag_index\":" + tagIndex + ",\"depth\":" + place.getDepth()
                    + ",\"place_object_version\":" + place.getPlaceObjectNum()
                    + ",\"move\":" + place.flagMove() + "}");
            }
        }
    }

    static SWF readSwf(String path) throws Exception {
        try (InputStream in = new BufferedInputStream(new FileInputStream(path))) {
            return new SWF(in, false);
        }
    }

    static void run(String[] args) throws Exception {
        String op=args[0], property=args[4], access=args[5];
        int selectedAbc=Integer.parseInt(args[2]), selectedMethod=Integer.parseInt(args[3]);
        offset=Integer.parseInt(args[6]); limit=Integer.parseInt(args[7]); budget=Integer.parseInt(args[8]);
        SWF swf = readSwf(args[1]);
        String summary = "";
        if (op.equals("linkage")) {
            linkage(swf.getTags(), new ArrayList<>(),
                new LinkageFilter(args[9], Integer.parseInt(args[10]), args[11]));
        } else if (op.equals("compare")) {
            SWF patched = args[1].equals(args[9]) ? swf : readSwf(args[9]);
            summary = ",\"summary\":" + Comparison.run(swf, patched, Boolean.parseBoolean(args[10]),
                Integer.parseInt(args[11]));
        } else {
            avm2(swf, op, property, access, selectedAbc, selectedMethod);
        }
        if(offset>total) throw new IllegalArgumentException("Offset exceeds result count");
        String next=offset+rows.size()<total?""+(offset+rows.size()):"null";
        System.out.println("{\"bridge_version\":1,\"results\":["+String.join(",",rows)
            +"],\"total\":"+total+",\"next_offset\":"+next+summary+"}");
    }

    static class Comparison {
        record MethodLocation(int abcIndex, ABC abc, MethodBody body, Map<Integer, String> identities,
                              Integer enclosingMethodId) {
            String json() {
                return "{\"abc_index\":" + abcIndex + ",\"method_id\":" + body.method_info
                    + (enclosingMethodId == null ? "" : ",\"enclosing_method_id\":" + enclosingMethodId) + "}";
            }
        }
        record AbcMethods(ABC abc, Map<Integer, String> identities) {}
        record ClosureSite(int methodId, String signature) {}
        record Inventory(Map<String, List<MethodLocation>> groups, List<MethodLocation> unanchored,
                         Map<String, Integer> methodCounts, Map<String, Integer> classCounts) {}
        record Fingerprint(String sha256, String metadataSha256, Set<String> unresolved) {}
        record InstructionKey(String opcode, List<String> operands) {}

        record InstructionSequence(List<AVM2Instruction> code, List<InstructionKey> keys, byte[] bytes) {
            String json(int index) {
                if (index < 0) return "null";
                AVM2Instruction ins = code.get(index);
                int start = Math.toIntExact(ins.getAddress());
                int end = index + 1 < code.size() ? Math.toIntExact(code.get(index + 1).getAddress()) : bytes.length;
                InstructionKey key = keys.get(index);
                return "{\"offset\":" + start + ",\"opcode\":" + q(key.opcode())
                    + ",\"operands\":" + (ins.operands == null ? "[]" : Arrays.toString(ins.operands))
                    + ",\"normalized_operands\":" + array(key.operands())
                    + ",\"bytes_hex\":" + q(HexFormat.of().formatHex(bytes, start, end)) + "}";
            }
        }

        static class InstructionDiff {
            final InstructionSequence original, patched;
            final int start, maxBytes;
            final List<String> changes = new ArrayList<>();
            int count, used;
            boolean pageFull;

            InstructionDiff(InstructionSequence original, InstructionSequence patched, int start, int maxBytes) {
                this.original = original;
                this.patched = patched;
                this.start = start;
                this.maxBytes = maxBytes;
            }

            void gap(int i, int endI, int j, int endJ) {
                while (i < endI || j < endJ) {
                    int a = i < endI ? i++ : -1;
                    int b = j < endJ ? j++ : -1;
                    if (a >= 0 && b >= 0 && original.keys().get(a).equals(patched.keys().get(b))) continue;
                    if (count++ < start || pageFull) continue;
                    String change = "{\"original\":" + original.json(a) + ",\"patched\":" + patched.json(b) + "}";
                    if (changes.size() >= 20 || used + change.length() + 1 > maxBytes) {
                        pageFull = true;
                    } else {
                        changes.add(change);
                        used += change.length() + 1;
                    }
                }
            }

            String json(boolean coarse) {
                int next = start + changes.size();
                String blocked = changes.isEmpty() && next < count
                    ? ",\"instruction_detail_error\":\"One instruction change exceeds the row budget; increase max_bytes or inspect the method directly.\""
                    : "";
                return ",\"instruction_changes\":[" + String.join(",", changes)
                    + "],\"instruction_change_count\":" + count + ",\"next_instruction_offset\":"
                    + (next < count ? Integer.toString(next) : "null")
                    + ",\"instruction_alignment\":" + q(coarse ? "positional" : "lcs") + blocked;
            }
        }

        static String signature(ABC abc, int methodId) {
            MethodInfo method = abc.method_info.get(methodId);
            List<String> params = Arrays.stream(method.param_types).mapToObj(i -> name(abc, i)).toList();
            return "\"parameter_types\":" + array(params) + ",\"return_type\":" + q(name(abc, method.ret_type));
        }

        static Map<Integer, Integer> anchorClosures(AbcMethods block, Map<String, Integer> methodCounts)
                throws NoSuchAlgorithmException {
            ABC abc = block.abc();
            Map<Integer, String> identities = block.identities();
            Set<Integer> anonymous = new HashSet<>();
            for (MethodBody body : abc.bodies)
                if (!identities.containsKey(body.method_info)) anonymous.add(body.method_info);
            if (anonymous.isEmpty()) return Map.of();

            Map<Integer, List<ClosureSite>> sites = new HashMap<>();
            Map<Integer, Integer> incoming = new HashMap<>();
            Map<Integer, String> signatures = new HashMap<>();
            for (MethodBody body : abc.bodies) {
                for (AVM2Instruction ins : body.getCode().code) {
                    if (!ins.definition.instructionName.equals("newfunction")) continue;
                    int child = ins.operands[0];
                    if (!anonymous.contains(child)) continue;
                    String signature = signatures.computeIfAbsent(child, id -> signature(abc, id));
                    sites.computeIfAbsent(body.method_info, id -> new ArrayList<>())
                        .add(new ClosureSite(child, signature));
                    incoming.merge(child, 1, Integer::sum);
                }
            }

            // Only globally unique named roots can anchor a chain of closures.
            ArrayDeque<Integer> queue = new ArrayDeque<>();
            for (int id : sites.keySet()) {
                String key = identities.get(id);
                if (key != null && methodCounts.get(key) == 1) queue.addLast(id);
            }
            Map<Integer, Integer> enclosing = new HashMap<>();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            while (!queue.isEmpty()) {
                int parent = queue.removeFirst();
                List<ClosureSite> children = sites.get(parent);
                if (children == null) continue;
                Map<String, Integer> siblingCounts = new HashMap<>();
                for (ClosureSite child : children) siblingCounts.merge(child.signature(), 1, Integer::sum);
                String parentKey = identities.get(parent);
                // A fixed-size parent key keeps identity size bounded for deeply nested closures.
                String parentHash = HexFormat.of().formatHex(digest.digest(parentKey.getBytes(StandardCharsets.UTF_8)));
                for (ClosureSite child : children) {
                    if (incoming.get(child.methodId()) != 1 || siblingCounts.get(child.signature()) != 1) continue;
                    String key = "{\"kind\":\"closure\",\"enclosing_identity_sha256\":" + q(parentHash)
                        + "," + child.signature() + "}";
                    identities.put(child.methodId(), key);
                    methodCounts.merge(key, 1, Integer::sum);
                    enclosing.put(child.methodId(), parent);
                    queue.addLast(child.methodId());
                }
            }
            return enclosing;
        }

        static Inventory inventory(SWF swf) throws NoSuchAlgorithmException {
            Map<String, List<MethodLocation>> groups = new TreeMap<>();
            List<MethodLocation> unanchored = new ArrayList<>();
            Map<String, Integer> methodCounts = new HashMap<>(), classCounts = new HashMap<>();
            List<AbcMethods> blocks = new ArrayList<>();
            for (var tag : swf.getAbcList()) {
                ABC abc = tag.getABC();
                Map<Integer, Set<String>> anchors = classOwners(abc);
                for (InstanceInfo instance : abc.instance_info)
                    classCounts.merge(name(abc, instance.name_index), 1, Integer::sum);
                for (ScriptInfo script : abc.script_info) {
                    traits(abc, script.traits, "script", anchors);
                    Set<String> exports = new TreeSet<>();
                    for (Trait trait : script.traits.traits)
                        exports.add(name(abc, trait.name_index));
                    if (!exports.isEmpty())
                        own(anchors, script.init_index, "script " + array(exports) + "::<initializer>");
                }
                Map<Integer, String> identities = new HashMap<>();
                anchors.forEach((id, names) -> {
                    String key = "{\"owners\":" + array(names) + "," + signature(abc, id) + "}";
                    identities.put(id, key);
                    methodCounts.merge(key, 1, Integer::sum);
                });
                blocks.add(new AbcMethods(abc, identities));
            }
            for (int abcIndex = 0; abcIndex < blocks.size(); abcIndex++) {
                AbcMethods block = blocks.get(abcIndex);
                Map<Integer, Integer> enclosing = anchorClosures(block, methodCounts);
                for (MethodBody body : block.abc().bodies) {
                    var method = new MethodLocation(abcIndex, block.abc(), body, block.identities(),
                        enclosing.get(body.method_info));
                    String key = block.identities().get(body.method_info);
                    if (key == null) unanchored.add(method);
                    else groups.computeIfAbsent(key, unused -> new ArrayList<>()).add(method);
                }
            }
            return new Inventory(groups, unanchored, methodCounts, classCounts);
        }

        static void token(MessageDigest digest, String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            for (int shift = 24; shift >= 0; shift -= 8)
                digest.update((byte) (bytes.length >>> shift));
            digest.update(bytes);
        }

        static String branchTarget(Map<Long, Integer> positions, long address, Set<String> unresolved) {
            Integer ordinal = positions.get(address);
            if (ordinal != null) return ordinal.toString();
            unresolved.add("invalid_branch_or_exception_target");
            return "?";
        }

        static String operand(MethodLocation method, Inventory inventory, AVM2Instruction ins,
                              int index, Set<String> unresolved) {
            ABC abc = method.abc();
            int value = ins.operands[index];
            return switch (ins.definition.operands[index]) {
                case AVM2Code.DAT_MULTINAME_INDEX -> name(abc, value);
                case AVM2Code.DAT_NAMESPACE_INDEX -> Multiname.namespaceToString(abc.constants, value);
                case AVM2Code.DAT_CLASS_INDEX -> {
                    String key = name(abc, abc.instance_info.get(value).name_index);
                    if (inventory.classCounts().get(key) == 1) yield key;
                    unresolved.add("ambiguous_class_operand");
                    yield "?";
                }
                case AVM2Code.DAT_METHOD_INDEX -> {
                    String key = method.identities().get(value);
                    if (key != null && inventory.methodCounts().get(key) == 1)
                        yield key;
                    unresolved.add("unanchored_or_ambiguous_method_operand");
                    yield "?";
                }
                case AVM2Code.DAT_FLOAT4_INDEX -> Arrays.toString(abc.constants.getFloat4(value).values);
                case AVM2Code.DAT_DOUBLE_INDEX -> Long.toHexString(Double.doubleToRawLongBits(abc.constants.getDouble(value)));
                case AVM2Code.DAT_FLOAT_INDEX -> Integer.toHexString(Float.floatToRawIntBits(abc.constants.getFloat(value)));
                case AVM2Code.DAT_STRING_INDEX -> nullableString(abc.constants.getString(value));
                case AVM2Code.DAT_INT_INDEX, AVM2Code.DAT_UINT_INDEX, AVM2Code.DAT_DECIMAL_INDEX ->
                    String.valueOf(ins.getParam(abc.constants, index));
                default -> Integer.toString(value);
            };
        }

        static Map<Long, Integer> instructionPositions(AVM2Code code) {
            Map<Long, Integer> positions = new HashMap<>();
            for (int i = 0; i < code.code.size(); i++) positions.put(code.code.get(i).getAddress(), i);
            positions.put(code.getEndOffset(), code.code.size());
            return positions;
        }

        static InstructionKey instructionKey(MethodLocation method, Inventory inventory, AVM2Instruction ins,
                                             Map<Long, Integer> positions, Set<String> unresolved) {
            List<String> operands = new ArrayList<>();
            var targets = ins.getOffsets();
            if (!targets.isEmpty()) {
                for (long address : targets) operands.add(branchTarget(positions, address, unresolved));
            } else if (ins.operands != null) {
                for (int i = 0; i < ins.operands.length; i++)
                    operands.add(operand(method, inventory, ins, i, unresolved));
            }
            return new InstructionKey(ins.definition.instructionName, operands);
        }

        static InstructionSequence instructions(MethodLocation method, Inventory inventory) {
            var code = method.body().getCode();
            var positions = instructionPositions(code);
            Set<String> unresolved = new HashSet<>();
            var keys = code.code.stream()
                .map(ins -> instructionKey(method, inventory, ins, positions, unresolved)).toList();
            return new InstructionSequence(code.code, keys, method.body().getCodeBytes());
        }

        static String instructionChanges(MethodLocation before, Inventory left, MethodLocation after,
                                         Inventory right, int start, int maxBytes) {
            var original = instructions(before, left);
            var patched = instructions(after, right);
            var a = original.keys();
            var b = patched.keys();
            var diff = new InstructionDiff(original, patched, start, maxBytes);
            int first = 0, endA = a.size(), endB = b.size();
            while (first < endA && first < endB && a.get(first).equals(b.get(first))) first++;
            while (endA > first && endB > first && a.get(endA - 1).equals(b.get(endB - 1))) {
                endA--;
                endB--;
            }
            int sizeA = endA - first, sizeB = endB - first;
            if (sizeA == 0 || sizeB == 0 || (long) (sizeA + 1) * (sizeB + 1) > 262_144) {
                diff.gap(first, endA, first, endB);
                return diff.json(sizeA > 0 && sizeB > 0);
            }

            // Bound the alignment table independently of the size of the SWF.
            int[][] lcs = new int[sizeA + 1][sizeB + 1];
            for (int i = sizeA - 1; i >= 0; i--)
                for (int j = sizeB - 1; j >= 0; j--)
                    lcs[i][j] = a.get(first + i).equals(b.get(first + j))
                        ? 1 + lcs[i + 1][j + 1] : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
            int i = 0, j = 0, gapA = first, gapB = first;
            while (i < sizeA && j < sizeB) {
                if (a.get(first + i).equals(b.get(first + j))) {
                    diff.gap(gapA, first + i, gapB, first + j);
                    gapA = first + ++i;
                    gapB = first + ++j;
                } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                    i++;
                } else {
                    j++;
                }
            }
            diff.gap(gapA, endA, gapB, endB);
            return diff.json(false);
        }

        static Fingerprint fingerprint(MethodLocation method, Inventory inventory) throws NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            Set<String> unresolved = new TreeSet<>();
            MethodBody body = method.body();
            ABC abc = method.abc();
            MethodInfo signature = abc.method_info.get(body.method_info);
            token(digest, Arrays.toString(new int[]{signature.flags, body.max_stack, body.max_regs,
                body.init_scope_depth, body.max_scope_depth}));
            token(digest, Integer.toString(signature.optional == null ? 0 : signature.optional.length));
            if (signature.optional != null)
                for (ValueKind option : signature.optional) token(digest, option.toASMString(abc));
            token(digest, Integer.toString(body.traits.traits.size()));
            for (Trait trait : body.traits.traits) {
                token(digest, name(abc, trait.name_index));
                token(digest, trait.getKindToStr());
                if (trait instanceof TraitSlotConst slot) {
                    token(digest, Integer.toString(slot.slot_id));
                    token(digest, name(abc, slot.type_index));
                    token(digest, slot.value_index == 0 ? "" :
                        new ValueKind(slot.value_index, slot.value_kind).toASMString(abc));
                } else {
                    unresolved.add("unsupported_body_trait");
                }
            }
            var code = body.getCode();
            Map<Long, Integer> positions = instructionPositions(code);
            for (ABCException handler : body.exceptions) {
                token(digest, "exception");
                token(digest, branchTarget(positions, handler.start, unresolved));
                token(digest, branchTarget(positions, handler.end, unresolved));
                token(digest, branchTarget(positions, handler.target, unresolved));
                token(digest, name(abc, handler.type_index));
                token(digest, name(abc, handler.name_index));
            }
            String metadata = HexFormat.of().formatHex(digest.digest());
            token(digest, metadata);
            for (AVM2Instruction ins : code.code) {
                InstructionKey key = instructionKey(method, inventory, ins, positions, unresolved);
                token(digest, key.opcode());
                token(digest, Integer.toString(key.operands().size()));
                for (String operand : key.operands()) token(digest, operand);
            }
            return new Fingerprint(HexFormat.of().formatHex(digest.digest()), metadata, unresolved);
        }

        static void row(Map<String, Integer> counts, boolean include, String status, String key, String detail) {
            counts.merge(status, 1, Integer::sum);
            if (include || !status.equals("unchanged"))
                emit("{\"status\":" + q(status) + ",\"identity\":" + key + "," + detail + "}");
        }

        static String location(MethodLocation method) {
            return method == null ? "null" : method.json();
        }

        static String run(SWF original, SWF patched, boolean include, int instructionOffset) throws NoSuchAlgorithmException {
            Inventory left = inventory(original), right = original == patched ? left : inventory(patched);
            Map<String, Integer> counts = new TreeMap<>();
            Set<String> keys = new TreeSet<>(left.groups().keySet());
            keys.addAll(right.groups().keySet());
            for (String key : keys) {
                var a = left.groups().getOrDefault(key, List.of());
                var b = right.groups().getOrDefault(key, List.of());
                if (a.size() > 1 || b.size() > 1
                    || left.methodCounts().getOrDefault(key, 0) > 1 || right.methodCounts().getOrDefault(key, 0) > 1) {
                    for (MethodLocation method : a)
                        row(counts, include, "ambiguous", key, "\"original\":" + method.json() + ",\"patched\":null");
                    for (MethodLocation method : b)
                        row(counts, include, "ambiguous", key, "\"original\":null,\"patched\":" + method.json());
                    continue;
                }
                MethodLocation before = a.isEmpty() ? null : a.get(0), after = b.isEmpty() ? null : b.get(0);
                String detail = "\"original\":" + location(before) + ",\"patched\":" + location(after);
                if (before == null || after == null) {
                    MethodLocation present = before == null ? after : before;
                    String status = present.enclosingMethodId() != null ? "unmatched"
                        : before == null ? "added" : "removed";
                    row(counts, include, status, key, detail);
                    continue;
                }
                Fingerprint x = fingerprint(before, left), y = fingerprint(after, right);
                Set<String> unresolved = new TreeSet<>(x.unresolved());
                unresolved.addAll(y.unresolved());
                String status = !unresolved.isEmpty() ? "indeterminate"
                    : x.sha256().equals(y.sha256()) ? "unchanged" : "changed";
                detail += ",\"original_body_sha256\":" + q(x.sha256())
                    + ",\"patched_body_sha256\":" + q(y.sha256()) + ",\"unresolved\":" + array(unresolved);
                if (status.equals("changed") && total >= offset && !full && rows.size() < limit) {
                    detail += ",\"metadata_changed\":" + !x.metadataSha256().equals(y.metadataSha256());
                    detail += instructionChanges(before, left, after, right, instructionOffset,
                        budget - 2048 - key.length() - detail.length() - 384);
                }
                row(counts, include, status, key, detail);
            }
            for (MethodLocation method : left.unanchored())
                row(counts, include, "unmatched", "null", "\"original\":" + method.json() + ",\"patched\":null");
            for (MethodLocation method : right.unanchored())
                row(counts, include, "unmatched", "null", "\"original\":null,\"patched\":" + method.json());
            StringJoiner summary = new StringJoiner(",", "{", "}");
            for (String status : List.of("changed", "unchanged", "added", "removed", "ambiguous", "indeterminate", "unmatched"))
                summary.add(q(status) + ":" + counts.getOrDefault(status, 0));
            return summary.toString();
        }
    }

    static void avm2(SWF swf, String op, String property, String access, int selectedAbc, int selectedMethod) {
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
    }
    public static void main(String[] args) {
        try { run(args); }
        catch(Throwable e) {
            System.err.println(e.getClass().getSimpleName()+": "+e.getMessage());
            System.exit(2);
        }
    }
}
