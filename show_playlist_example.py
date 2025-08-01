#!/usr/bin/env python3
"""
Example script to show the new playlist structure returned by create_random_playlist.
"""

import json
import sys
import os

# Add the tensorprox directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tensorprox'))

from tensorprox.utils.utils import create_random_playlist, generate_random_hashes

def show_playlist_example():
    """Show an example of the new playlist structure."""
    
    print("🎵 Example Playlist Structure from create_random_playlist()")
    print("=" * 60)
    
    # Generate label hashes
    label_hashes = generate_random_hashes()
    
    # Create multiple examples to show variety
    for example_num in range(1, 4):
        print(f"\n📋 Example {example_num}:")
        print("-" * 40)
        
        # Create a playlist with different seeds for variety
        playlist = create_random_playlist(
            total_seconds=300,  # 5 minutes
            label_hashes=label_hashes,
            role="aggressive",
            seed=12345 + example_num  # Different seed for each example
        )
        
        # Show the complete JSON structure
        print("📋 Complete JSON Structure:")
        print(json.dumps(playlist, indent=2))
        
        # Show the attack sequence clearly
        attack = playlist["attack_playlist"]
        print("\n🔴 ATTACK SEQUENCE (Alternating Pattern):")
        
        current_time = 0
        for i, entry in enumerate(attack):
            if entry['name'] == 'pause':
                print(f"   {i+1:2d}. PAUSE     for {entry['duration']:3d}s (at {current_time:3d}s)")
            else:
                print(f"   {i+1:2d}. ATTACK    {entry['name']:20s} for {entry['duration']:3d}s (at {current_time:3d}s)")
            current_time += entry['duration']
        
        # Show summary
        attacks = [e for e in attack if e['name'] != 'pause']
        pauses = [e for e in attack if e['name'] == 'pause']
        print(f"\n📊 Summary:")
        print(f"   - Total entries: {len(attack)}")
        print(f"   - Attacks: {len(attacks)}")
        print(f"   - Pauses: {len(pauses)}")
        print(f"   - Pattern: {'Attack' if attack[0]['name'] != 'pause' else 'Pause'} → {'Pause' if attack[0]['name'] != 'pause' else 'Attack'} → ...")
    
    print("\n" + "=" * 60)
    print("✅ Key Features:")
    print("   - Benign traffic runs continuously (TCP + UDP)")
    print("   - Both TCP and UDP benign traffic use the same label hash")
    print("   - Attack sequence alternates: Attack ↔ Pause ↔ Attack ↔ Pause...")
    print("   - No consecutive attacks or pauses")
    print("   - Each traffic generator gets independent sequences")
    print("   - Random durations (60-180 seconds) for each entry")

if __name__ == "__main__":
    show_playlist_example() 