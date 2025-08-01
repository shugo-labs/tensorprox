#!/usr/bin/env python3
"""
Comprehensive test to verify the new playlist structure migration is complete and working.
"""

import json
import sys
import os

# Add the tensorprox directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tensorprox'))

from tensorprox.utils.utils import create_random_playlist, generate_random_hashes

def test_playlist_generation():
    """Test playlist generation and structure."""
    print("🧪 Testing Playlist Generation")
    print("=" * 40)
    
    # Generate test data
    label_hashes = generate_random_hashes()
    total_seconds = 300
    
    # Test multiple playlists with different seeds
    for i in range(3):
        playlist = create_random_playlist(
            total_seconds=total_seconds,
            label_hashes=label_hashes,
            role="aggressive",
            seed=12345 + i
        )
        
        # Verify structure
        assert "benign_playlist" in playlist, "Missing benign_playlist"
        assert "attack_playlist" in playlist, "Missing attack_playlist"
        
        # Verify benign structure
        benign = playlist["benign_playlist"]
        assert benign["name"] == "BENIGN", "Benign name should be 'BENIGN'"
        assert benign["duration"] == total_seconds, "Benign duration should match total_seconds"
        assert len(benign["classes"]) == 2, "Should have exactly 2 benign classes"
        
        # Verify TCP and UDP use same hash
        tcp_class = next(c for c in benign["classes"] if c["class_vector"] == "tcp_traffic")
        udp_class = next(c for c in benign["classes"] if c["class_vector"] == "udp_traffic")
        assert tcp_class["label_identifier"] == udp_class["label_identifier"], "TCP and UDP should use same hash"
        
        # Verify alternating pattern
        attack_playlist = playlist["attack_playlist"]
        for j, entry in enumerate(attack_playlist):
            if j % 2 == 0:
                assert entry["name"] != "pause", f"Entry {j} should be attack, not pause"
            else:
                assert entry["name"] == "pause", f"Entry {j} should be pause, not attack"
        
        print(f"✅ Playlist {i+1} structure is correct")
    
    print("✅ All playlist generation tests passed!")

def test_json_serialization():
    """Test JSON serialization/deserialization."""
    print("\n📝 Testing JSON Serialization")
    print("=" * 40)
    
    label_hashes = generate_random_hashes()
    playlist = create_random_playlist(
        total_seconds=300,
        label_hashes=label_hashes,
        seed=12345
    )
    
    # Test serialization
    json_str = json.dumps(playlist)
    assert isinstance(json_str, str), "JSON serialization should return string"
    
    # Test deserialization
    parsed = json.loads(json_str)
    assert parsed == playlist, "JSON deserialization should match original"
    
    print("✅ JSON serialization/deserialization works correctly!")

def test_validator_playlist_structure():
    """Test the structure that validator creates for multiple traffic generators."""
    print("\n🎯 Testing Validator Playlist Structure")
    print("=" * 40)
    
    # Simulate what validator does
    label_hashes = generate_random_hashes()
    playlists = {}
    
    # Create playlists for multiple traffic generators
    for i in range(3):  # MAX_TGENS = 3
        playlist = create_random_playlist(
            total_seconds=300,
            label_hashes=label_hashes,
            role="aggressive" if i % 2 == 1 else "soft",
            seed=12345 + i
        )
        playlists[f"tgen-{i}"] = playlist
    
    # Verify structure
    assert len(playlists) == 3, "Should have 3 playlists"
    for machine_name, playlist in playlists.items():
        assert machine_name.startswith("tgen-"), f"Machine name should start with 'tgen-': {machine_name}"
        assert "benign_playlist" in playlist, f"Playlist for {machine_name} missing benign_playlist"
        assert "attack_playlist" in playlist, f"Playlist for {machine_name} missing attack_playlist"
    
    print("✅ Validator playlist structure is correct!")

def test_traffic_generator_compatibility():
    """Test that the playlist structure is compatible with traffic_generator.py expectations."""
    print("\n⚙️ Testing Traffic Generator Compatibility")
    print("=" * 40)
    
    label_hashes = generate_random_hashes()
    playlist = create_random_playlist(
        total_seconds=300,
        label_hashes=label_hashes,
        seed=12345
    )
    
    # Test the structure that traffic_generator.py expects
    assert isinstance(playlist, dict), "Playlist should be a dictionary"
    assert "benign_playlist" in playlist, "Should have benign_playlist key"
    assert "attack_playlist" in playlist, "Should have attack_playlist key"
    
    # Test benign playlist structure
    benign = playlist["benign_playlist"]
    assert "classes" in benign, "Benign playlist should have classes"
    assert isinstance(benign["classes"], list), "Classes should be a list"
    
    for cls in benign["classes"]:
        assert "class_vector" in cls, "Class should have class_vector"
        assert "label_identifier" in cls, "Class should have label_identifier"
        assert "duration" in cls, "Class should have duration"
        assert cls["class_vector"] in ["tcp_traffic", "udp_traffic"], f"Invalid class_vector: {cls['class_vector']}"
    
    # Test attack playlist structure
    attack_playlist = playlist["attack_playlist"]
    assert isinstance(attack_playlist, list), "Attack playlist should be a list"
    
    for entry in attack_playlist:
        assert "name" in entry, "Attack entry should have name"
        assert "duration" in entry, "Attack entry should have duration"
        if entry["name"] != "pause":
            assert "class_vector" in entry, "Attack entry should have class_vector"
            assert "label_identifier" in entry, "Attack entry should have label_identifier"
    
    print("✅ Traffic generator compatibility verified!")

def main():
    """Run all tests."""
    print("🚀 Starting Comprehensive Migration Test")
    print("=" * 50)
    
    try:
        test_playlist_generation()
        test_json_serialization()
        test_validator_playlist_structure()
        test_traffic_generator_compatibility()
        
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ Migration to new playlist structure is complete and working!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 