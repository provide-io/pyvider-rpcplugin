#!/usr/bin/env python3
"""
Comprehensive internal link checker for pyvider-rpcplugin documentation.
Checks all markdown files for broken internal links, missing files, and invalid anchors.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote

def find_markdown_files(docs_dir: str) -> list[Path]:
    """Find all markdown files in the docs directory."""
    docs_path = Path(docs_dir)
    return list(docs_path.rglob("*.md"))

def extract_internal_links(file_path: Path) -> list[tuple[int, str, str, str]]:
    """
    Extract internal links from a markdown file.
    Returns list of (line_number, link_text, link_path, anchor)
    """
    links = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Pattern to match markdown links [text](path) or [text](path#anchor)
        # Exclude external links (http/https/mailto/etc)
        link_pattern = r'\[([^\]]*)\]\(([^)]+)\)'
        
        for line_num, line in enumerate(content.split('\n'), 1):
            matches = re.finditer(link_pattern, line)
            for match in matches:
                link_text = match.group(1)
                full_link = match.group(2).strip()
                
                # Skip external links
                if (full_link.startswith('http://') or 
                    full_link.startswith('https://') or
                    full_link.startswith('mailto:') or
                    full_link.startswith('ftp://') or
                    full_link.startswith('tel:')):
                    continue
                
                # Skip fragment-only links (same page anchors)
                if full_link.startswith('#'):
                    continue
                    
                # Parse link path and anchor
                if '#' in full_link:
                    link_path, anchor = full_link.split('#', 1)
                    anchor = anchor.strip()
                else:
                    link_path = full_link
                    anchor = ''
                
                # Decode URL encoding
                link_path = unquote(link_path).strip()
                
                # Skip empty paths
                if not link_path:
                    continue
                    
                links.append((line_num, link_text, link_path, anchor))
                
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        
    return links

def resolve_link_path(source_file: Path, link_path: str, docs_root: Path) -> Path:
    """Resolve relative link path to absolute path."""
    if link_path.startswith('/'):
        # Absolute path from docs root
        return docs_root / link_path.lstrip('/')
    else:
        # Relative path from source file directory
        return (source_file.parent / link_path).resolve()

def extract_headings(file_path: Path) -> set[str]:
    """Extract all heading anchors from a markdown file."""
    headings = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Pattern for markdown headings
        heading_pattern = r'^#+\s+(.+)$'
        
        for line in content.split('\n'):
            match = re.match(heading_pattern, line.strip())
            if match:
                heading_text = match.group(1).strip()
                # Convert to anchor format (lowercase, replace spaces/special chars with hyphens)
                anchor = re.sub(r'[^\w\s-]', '', heading_text.lower())
                anchor = re.sub(r'[-\s]+', '-', anchor).strip('-')
                headings.add(anchor)
                
    except Exception as e:
        print(f"Error reading headings from {file_path}: {e}")
        
    return headings

def check_links(docs_dir: str) -> dict[str, list]:
    """Check all internal links in documentation."""
    docs_root = Path(docs_dir)
    md_files = find_markdown_files(docs_dir)
    
    results = {
        'broken_files': [],
        'broken_anchors': [],
        'valid_links': [],
        'file_stats': {}
    }
    
    print(f"Found {len(md_files)} markdown files to check...")
    
    for md_file in md_files:
        print(f"\nChecking {md_file.relative_to(docs_root)}...")
        
        links = extract_internal_links(md_file)
        results['file_stats'][str(md_file.relative_to(docs_root))] = {
            'total_links': len(links),
            'broken_files': 0,
            'broken_anchors': 0,
            'valid_links': 0
        }
        
        for line_num, link_text, link_path, anchor in links:
            # Resolve the target file path
            target_path = resolve_link_path(md_file, link_path, docs_root)
            
            # Check if target file exists
            if not target_path.exists():
                results['broken_files'].append({
                    'source_file': str(md_file.relative_to(docs_root)),
                    'line_number': line_num,
                    'link_text': link_text,
                    'link_path': link_path,
                    'resolved_path': str(target_path.relative_to(docs_root)) if docs_root in target_path.parents else str(target_path),
                    'error': 'File does not exist'
                })
                results['file_stats'][str(md_file.relative_to(docs_root))]['broken_files'] += 1
                continue
            
            # If there's an anchor, check if it exists in the target file
            if anchor:
                headings = extract_headings(target_path)
                if anchor not in headings:
                    results['broken_anchors'].append({
                        'source_file': str(md_file.relative_to(docs_root)),
                        'line_number': line_num,
                        'link_text': link_text,
                        'link_path': link_path,
                        'anchor': anchor,
                        'target_file': str(target_path.relative_to(docs_root)),
                        'available_anchors': sorted(headings),
                        'error': 'Anchor does not exist'
                    })
                    results['file_stats'][str(md_file.relative_to(docs_root))]['broken_anchors'] += 1
                    continue
            
            # Link is valid
            results['valid_links'].append({
                'source_file': str(md_file.relative_to(docs_root)),
                'line_number': line_num,
                'link_text': link_text,
                'link_path': link_path,
                'anchor': anchor,
                'target_file': str(target_path.relative_to(docs_root))
            })
            results['file_stats'][str(md_file.relative_to(docs_root))]['valid_links'] += 1
    
    return results

def print_results(results: dict):
    """Print comprehensive link check results."""
    broken_files = results['broken_files']
    broken_anchors = results['broken_anchors']
    valid_links = results['valid_links']
    
    print(f"\n" + "="*80)
    print("LINK CHECK RESULTS")
    print("="*80)
    
    total_links = len(broken_files) + len(broken_anchors) + len(valid_links)
    print(f"Total internal links found: {total_links}")
    print(f"Valid links: {len(valid_links)}")
    print(f"Broken file links: {len(broken_files)}")
    print(f"Broken anchor links: {len(broken_anchors)}")
    
    if broken_files:
        print(f"\n" + "="*50)
        print("BROKEN FILE LINKS")
        print("="*50)
        
        for i, broken in enumerate(broken_files, 1):
            print(f"\n{i}. {broken['source_file']}:{broken['line_number']}")
            print(f"   Link text: '{broken['link_text']}'")
            print(f"   Link path: '{broken['link_path']}'")
            print(f"   Resolved to: {broken['resolved_path']}")
            print(f"   Error: {broken['error']}")
            
            # Suggest corrections
            suggest_corrections(broken)
    
    if broken_anchors:
        print(f"\n" + "="*50)
        print("BROKEN ANCHOR LINKS")
        print("="*50)
        
        for i, broken in enumerate(broken_anchors, 1):
            print(f"\n{i}. {broken['source_file']}:{broken['line_number']}")
            print(f"   Link text: '{broken['link_text']}'")
            print(f"   Link path: '{broken['link_path']}'")
            print(f"   Missing anchor: #{broken['anchor']}")
            print(f"   Target file: {broken['target_file']}")
            print(f"   Available anchors: {broken['available_anchors'][:5]}{'...' if len(broken['available_anchors']) > 5 else ''}")
            
            # Suggest similar anchors
            suggest_anchor_corrections(broken)
    
    # Print file statistics
    print(f"\n" + "="*50)
    print("FILE STATISTICS")
    print("="*50)
    
    for file_path, stats in results['file_stats'].items():
        if stats['total_links'] > 0:
            issues = stats['broken_files'] + stats['broken_anchors']
            status = "❌" if issues > 0 else "✅"
            print(f"{status} {file_path}: {stats['total_links']} links ({stats['valid_links']} valid, {issues} broken)")

def suggest_corrections(broken: dict):
    """Suggest possible corrections for broken file links."""
    link_path = broken['link_path']
    
    # Common corrections
    suggestions = []
    
    # Check if it's a case issue
    if link_path.lower().endswith('.md'):
        suggestions.append(f"Check file case: {link_path}")
    
    # Check if missing .md extension
    if not link_path.endswith('.md') and not link_path.endswith('/'):
        suggestions.append(f"Try adding .md: {link_path}.md")
    
    # Check if it should be index.md
    if link_path.endswith('/'):
        suggestions.append(f"Try: {link_path}index.md")
    
    if suggestions:
        print(f"   Suggestions: {', '.join(suggestions)}")

def suggest_anchor_corrections(broken: dict):
    """Suggest similar anchors for broken anchor links."""
    target_anchor = broken['anchor'].lower()
    available = broken['available_anchors']
    
    # Find similar anchors
    similar = []
    for anchor in available:
        if target_anchor in anchor.lower() or anchor.lower() in target_anchor:
            similar.append(anchor)
    
    if similar:
        print(f"   Similar anchors: {similar[:3]}")

if __name__ == "__main__":
    docs_directory = "/Users/tim/code/gh/provide-io/pyvider-rpcplugin/docs"
    results = check_links(docs_directory)
    print_results(results)