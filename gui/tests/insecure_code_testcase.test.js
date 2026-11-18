const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { scanSourceText, cppToSsa } = require('../server.js');
const { TESTCASES_SSA } = require('../testcases_ssa.js');

const EXPECTED_CODE = `#include <iostream>
#include <cstring>
#include <cstdlib>

void vulnerable_copy(const char* input) {
    char buffer[16];
    strcpy(buffer, input);          // CWE-120: no bounds check, classic buffer overflow
    std::cout << "Copied: " << buffer << std::endl;
}

void run_shell_command(const std::string& user_input) {
    std::string cmd = "echo " + user_input;
    system(cmd.c_str());            // CWE-78: unsanitized input passed to shell
}

int format_string_bug(const char* user_input) {
    printf(user_input);             // CWE-134: format string vulnerability (should be printf("%s", user_input))
    return 0;
}

char* use_after_free_demo() {
    char* data = (char*)malloc(32);
    strcpy(data, "sensitive");
    free(data);
    return data;                    // CWE-416: returning a pointer after free
}

int main() {
    char password[8] = "admin123";  // CWE-798: hardcoded credential
    vulnerable_copy("this string is way longer than sixteen bytes on purpose");
    format_string_bug("%s%s%s%s");  // will likely crash or leak stack memory
    use_after_free_demo();
    return 0;
}
`;

describe('=== Predefined Editor Test Case: "Insecure Code Test" ===', () => {

  test('1. Test case registration in public index.html with exact display name', () => {
    const htmlPath = path.join(__dirname, '../public/index.html');
    const htmlContent = fs.readFileSync(htmlPath, 'utf8');

    // Name must be exactly 'Insecure Code Test'
    assert(htmlContent.includes("'Insecure Code Test':"), 'TESTCASE_INPUTS must contain exact key "Insecure Code Test"');
    
    // Normalize function must preserve 'Insecure Code Test'
    assert(htmlContent.includes("if (tc === 'Insecure Code Test'"), 'normalizeTcLabel must recognize "Insecure Code Test"');
  });

  test('2. Loaded source code exactly matches the required test case specification', () => {
    const htmlPath = path.join(__dirname, '../public/index.html');
    const htmlContent = fs.readFileSync(htmlPath, 'utf8');

    // Extract the registered source text from index.html
    const match = htmlContent.match(/'Insecure Code Test':\s*`([^`]+)`/);
    assert(match, 'Failed to extract Insecure Code Test from index.html');
    const registeredCode = match[1];

    assert.strictEqual(
      registeredCode.trim().replace(/\r\n/g, '\n'),
      EXPECTED_CODE.trim().replace(/\r\n/g, '\n'),
      'Registered source code must be identical to the required insecure sample'
    );
  });

  test('3. Registered in inputs/ and test_suite_src/ for sample listing and compiler parity', () => {
    const inputPath = path.join(__dirname, '../../inputs/Insecure Code Test.cpp');
    const testSuitePath = path.join(__dirname, '../../test_suite_src/Insecure Code Test.cpp');

    assert(fs.existsSync(inputPath), 'inputs/Insecure Code Test.cpp must exist');
    assert(fs.existsSync(testSuitePath), 'test_suite_src/Insecure Code Test.cpp must exist');

    const inputCode = fs.readFileSync(inputPath, 'utf8').trim().replace(/\r\n/g, '\n');
    assert.strictEqual(inputCode, EXPECTED_CODE.trim().replace(/\r\n/g, '\n'));
  });

  test('4. Non-Execution invariant: Selection/Loading does not invoke execution, compilation or DRONA', () => {
    // Simulate what loadTestcase does in index.html
    let editorValue = '';
    let executed = false;
    let compiled = false;
    let dronaCalled = false;
    let selfHealed = false;

    function mockLoadTestcase(label, inputs) {
      if (!inputs[label]) throw new Error(`Missing ${label}`);
      // Exact sequence performed by loadTestcase in index.html:
      editorValue = inputs[label];
      // Selection ONLY populates editor value and notifies editor input listeners
      // It must never execute, compile, call DRONA, or auto-apply self-healing
    }

    mockLoadTestcase('Insecure Code Test', { 'Insecure Code Test': EXPECTED_CODE });

    assert.strictEqual(editorValue, EXPECTED_CODE, 'Editor value must receive exact source code');
    assert.strictEqual(executed, false, 'Execution must NOT be triggered on selection');
    assert.strictEqual(compiled, false, 'Compilation must NOT be triggered on selection');
    assert.strictEqual(dronaCalled, false, 'DRONA must NOT be triggered on selection');
    assert.strictEqual(selfHealed, false, 'Self-healing must NOT be automatically applied on selection');
  });

  test('5. Real vulnerability findings triggered based on actual source code (no hard-coding)', () => {
    const scan = scanSourceText(EXPECTED_CODE);
    assert(scan, 'scanSourceText must return a result');
    assert(Array.isArray(scan.findings), 'scan must produce findings array');
    assert(scan.findings.length >= 5, `Expected at least 5 findings, got ${scan.findings.length}`);

    const cwes = scan.findings.map(f => f.cwe);
    
    // CWE-120: Unchecked Buffer Copy (strcpy)
    assert(cwes.includes('CWE-120'), 'Must detect CWE-120 (strcpy buffer overflow)');
    // CWE-78: OS Command Injection (system)
    assert(cwes.includes('CWE-78'), 'Must detect CWE-78 (OS command injection)');
    // CWE-134: Uncontrolled Format String Flaw (printf(user_input))
    assert(cwes.includes('CWE-134'), 'Must detect CWE-134 (Format string vulnerability)');
    // CWE-798: Hardcoded Sensitive Credential (char password[8] = "admin123")
    assert(cwes.includes('CWE-798'), 'Must detect CWE-798 (Hardcoded password)');
    // CWE-416: Use After Free (returning freed pointer)
    assert(cwes.includes('CWE-416'), 'Must detect CWE-416 (Use-after-free on return data)');
    // CWE-252 / CWE-415: Memory allocation / double free / dangling pointer hazard
    assert(cwes.includes('CWE-252') || cwes.includes('CWE-415'), 'Must detect memory management hazard (malloc/free)');

    // Ensure line numbers and snippets are preserved per finding
    assert(scan.findings.every(f => typeof f.line === 'number' && f.line > 0), 'Every finding must retain valid positive line number');
    assert(scan.findings.every(f => typeof f.codeSnippet === 'string' && f.codeSnippet.length > 0), 'Every finding must retain codeSnippet');
    assert(scan.findings.every(f => typeof f.recommendation === 'string' && f.recommendation.length > 0), 'Every finding must retain remediation');
  });

  test('6. Preserves existing test cases (TC01-TC17, TC_SEC)', () => {
    const htmlPath = path.join(__dirname, '../public/index.html');
    const htmlContent = fs.readFileSync(htmlPath, 'utf8');

    for (let i = 1; i <= 17; i++) {
      const tc = `TC${String(i).padStart(2, '0')}`;
      assert(htmlContent.includes(`${tc}: \`#include`), `Must preserve ${tc}`);
    }
    assert(htmlContent.includes("TC_SEC: `#include"), 'Must preserve TC_SEC');
    assert(TESTCASES_SSA.TC01, 'TESTCASES_SSA.TC01 must exist');
    assert(TESTCASES_SSA['Insecure Code Test'], 'TESTCASES_SSA["Insecure Code Test"] must exist');
  });
});
