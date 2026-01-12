from kfast_system import compile_and_run, KernelRuntime, CommandStore

# Shared kernel for all execution
_kernel: KernelRuntime = None


def get_kernel() -> KernelRuntime:
    """Get or create the shared kernel runtime."""
    global _kernel
    if _kernel is None:
        _kernel = KernelRuntime(store=CommandStore())
    return _kernel


def execute(user_input: str):
    """Execute user input.
    
    If input looks like KFAST code (contains KFAST glyphs), run it through the VM.
    Otherwise, print the input as before.
    """
    # Check if input contains KFAST glyphs
    kfast_glyphs = {"⟦", "⟧", "⟨", "⟩", "⟶", "⋄", "∷", "⚙", "■", "✓", "☍", "☊", "⌁", "☰", "↻", "ƒ"}
    is_kfast_code = any(glyph in user_input for glyph in kfast_glyphs)
    
    if is_kfast_code:
        try:
            result = compile_and_run(user_input, kernel=get_kernel())
            print("EXECUTOR [KFAST]:", result)
            return result
        except Exception as e:
            print(f"EXECUTOR [ERROR]: {e}")
            return None
    else:
        print("EXECUTOR:", user_input)
        return user_input
