import sys
import os

def print_usage():
    """Display usage instructions"""
    print("Usage: python xor_tool.py <mode> <input_file> <output_file> <hex_key>")
    print("  mode: 'encrypt' or 'decrypt'")
    print("  input_file: path to input file")
    print("  output_file: path to output file")
    print("  hex_key: single byte in hex format (e.g., A5, 1F, 7B, ff)")
    print("\nExamples:")
    print("  python xor_tool.py encrypt plain.txt encrypted.bin A5")
    print("  python xor_tool.py decrypt encrypted.bin decrypted.txt A5")

def validate_hex_key(hex_str):
    """
    Validate and convert hex key to integer
    
    Args:
        hex_str: Hexadecimal string (e.g., 'A5', '1f', '7B', '0xFF')
    
    Returns:
        int: Integer value of the hex key (0-255)
    """
    try:
        # Remove any '0x' prefix if present
        if hex_str.startswith('0x') or hex_str.startswith('0X'):
            hex_str = hex_str[2:]
        
        # Convert hex to integer
        key_int = int(hex_str, 16)
        
        # Validate byte range
        if key_int < 0 or key_int > 255:
            raise ValueError(f"Key value {key_int} out of range (must be 0-255)")
        
        return key_int
    
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(f"Invalid hex format: '{hex_str}'. Use format like A5, 1F, 7B")
        raise

def format_hex_bytes(byte_data, max_bytes=16):
    """
    Format bytes as hexadecimal string for display
    
    Args:
        byte_data: Bytes to format
        max_bytes: Maximum number of bytes to show
    
    Returns:
        str: Formatted hex string
    """
    # Take only first max bytes
    preview = byte_data[:max_bytes]
    
    # Format each byte as 2-digit hex
    hex_bytes = [f"{b:02X}" for b in preview]
    
    # Join with spaces
    return ' '.join(hex_bytes)

def xor_file(input_file, output_file, key_byte, mode):
    """
    Apply XOR operation to entire file
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        key_byte: XOR key as integer (0-255)
        mode: Operation mode ('encrypt' or 'decrypt')
    
    Returns:
        tuple: (input_size, output_preview_bytes)
    """
    try:
        # Check if input file exists
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Get file size
        input_size = os.path.getsize(input_file)
        
        # Open input file in binary mode
        with open(input_file, 'rb') as f_in:
            # Read entire file content
            file_data = f_in.read()
        
        # Apply XOR operation to each byte
        # Using list comprehension for efficiency
        result_data = bytes([b ^ key_byte for b in file_data])
        
        # Get first 16 bytes of result for display
        output_preview = result_data[:16]
        
        # Write to output file in binary mode
        with open(output_file, 'wb') as f_out:
            f_out.write(result_data)
        
        return input_size, output_preview
    
    except IOError as e:
        raise IOError(f"File operation error: {e}")

def main():
    """Main function to handle command-line arguments"""
    
    # Check number of arguments
    if len(sys.argv) != 5:
        print("Error: Incorrect number of arguments")
        print_usage()
        sys.exit(1)
    
    # Parse command-line arguments
    mode = sys.argv[1].lower()
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    hex_key = sys.argv[4]
    
    # Validate mode
    if mode not in ['encrypt', 'decrypt']:
        print(f"Error: Invalid mode '{mode}'. Must be 'encrypt' or 'decrypt'")
        print_usage()
        sys.exit(1)
    
    try:
        # Convert hex key to integer
        key_byte = validate_hex_key(hex_key)
        
        print("\n" + "=" * 60)
        print(" XOR FILE TOOL")
        print("=" * 60)
        
        # Perform XOR operation
        input_size, output_preview = xor_file(input_file, output_file, key_byte, mode)
        
        # Display execution information (requirements 7a-7d)
        print(f"Operation: {mode.upper()}")
        print(f"Key used: 0x{key_byte:02X} ({key_byte} decimal)")
        print(f"Input file size: {input_size} bytes")
        print(f"First 16 bytes of output (hex): {format_hex_bytes(output_preview)}")
        
        print("=" * 60)
        print(f"Output written to: {output_file}")
        
        # Additional useful information
        if input_size == 0:
            print("\nWarning: Input file is empty!")
        
        # Note about XOR property
        print("\n" + "-" * 60)
        print("NOTE: XOR is reversible! Running the same operation")
        print(f"on '{output_file}' with the same key will restore the original.")
        print("-" * 60)
        
    except ValueError as e:
        print(f"\nError: {e}")
        print_usage()
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
