#!/usr/bin/env python3
"""
Test script to verify the new playlist structure works correctly with the entire pipeline.
"""

import json
import sys
import os

# Add the tensorprox directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tensorprox'))

from tensorprox.utils.utils import create_random_playlist, generate_random_hashes

def test_new_playlist_integration():
    """Test that the new playlist structure works correctly with the entire pipeline."""
    
    print("🧪 Testing New Playlist Structure Integration")
    print("=" * 60)
    
    # Generate label hashes
    label_hashes = generate_random_hashes()
    
    # Create a playlist with the new structure
    playlist = create_random_playlist(
        total_seconds=300,  # 5 minutes
        label_hashes=label_hashes,
        role="aggressive",
        seed=12345
    )
    
    print("📋 Generated Playlist Structure:")
    print(json.dumps(playlist, indent=2))
    
    print("\n" + "=" * 60)
    print("🔍 Validation Checks:")
    
    # Check 1: Verify structure
    assert "benign_playlist" in playlist, "❌ Missing benign_playlist"
    assert "attack_playlist" in playlist, "❌ Missing attack_playlist"
    print("✅ Structure validation passed")
    
    # Check 2: Verify benign playlist
    benign = playlist["benign_playlist"]
    assert "name" in benign, "❌ Missing name in benign playlist"
    assert "duration" in benign, "❌ Missing duration in benign playlist"
    assert "classes" in benign, "❌ Missing classes in benign playlist"
    assert len(benign["classes"]) == 2, "❌ Should have 2 classes (TCP and UDP)"
    
    # Check 3: Verify TCP and UDP have the same hash (both are BENIGN)
    tcp_hash = benign["classes"][0]["label_identifier"]
    udp_hash = benign["classes"][1]["label_identifier"]
    assert tcp_hash == udp_hash, "❌ TCP and UDP should have the same hash (both are BENIGN)"
    print("✅ TCP and UDP use the same label hash (both are BENIGN)")
    
    # Check 4: Verify attack playlist alternates
    attack = playlist["attack_playlist"]
    assert len(attack) > 0, "❌ Attack playlist should not be empty"
    
    # Check for alternating pattern
    for i in range(len(attack) - 1):
        current = attack[i]["name"]
        next_entry = attack[i + 1]["name"]
        assert (current == "pause" and next_entry != "pause") or (current != "pause" and next_entry == "pause"), \
            f"❌ Not alternating: {current} followed by {next_entry}"
    print("✅ Attack playlist alternates correctly")
    
    # Check 5: Verify all attack entries have proper structure
    for entry in attack:
        assert "name" in entry, "❌ Missing name in attack entry"
        assert "duration" in entry, "❌ Missing duration in attack entry"
        if entry["name"] != "pause":
            assert "class_vector" in entry, "❌ Missing class_vector in attack entry"
            assert "label_identifier" in entry, "❌ Missing label_identifier in attack entry"
    print("✅ All attack entries have proper structure")
    
    # Check 6: Verify label hashes are from correct categories
    for entry in attack:
        if entry["name"] != "pause":
            label_id = entry["label_identifier"]
            attack_type = entry["name"]
            if attack_type.startswith("UDP"):
                assert label_id in label_hashes["UDP_FLOOD"], f"❌ UDP attack should use UDP_FLOOD hash"
            elif attack_type.startswith("TCP"):
                assert label_id in label_hashes["TCP_SYN_FLOOD"], f"❌ TCP attack should use TCP_SYN_FLOOD hash"
    print("✅ Attack entries use correct label hash categories")
    
    # Check 7: Verify benign entries use BENIGN hashes
    for cls in benign["classes"]:
        label_id = cls["label_identifier"]
        assert label_id in label_hashes["BENIGN"], f"❌ Benign traffic should use BENIGN hash"
    print("✅ Benign entries use correct label hash categories")
    
    print("\n" + "=" * 60)
    print("✅ All validation checks passed!")
    print("\n📊 Summary:")
    print(f"   - Benign traffic: {len(benign['classes'])} types (TCP + UDP)")
    print(f"   - Attack sequence: {len(attack)} entries")
    print(f"   - Attacks: {len([e for e in attack if e['name'] != 'pause'])}")
    print(f"   - Pauses: {len([e for e in attack if e['name'] == 'pause'])}")
    print(f"   - Total duration: {benign['duration']} seconds")
    print("\n🎯 The new playlist structure is ready for production!")

if __name__ == "__main__":
    test_new_playlist_integration() 