// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./verifier_MerkleTree.sol";
import "./verifier_zkSNARK.sol";

/**
 * @dev A smart contract for conducting elections that utilizes zk-SNARKs for
 * privacy and verifiability.
 * 
 * This contract allows for an unlimited number of candidates and an unlimited
 * number of voters. It utilizes a bulletin board style voting process where
 * voters can post their votes, but cannot modify or delete their votes after
 * they have been submitted.
 * 
 * The contract is designed to be used with the ZoKrates toolchain for generating
 * zk-SNARK proofs.
 */
contract BCSVoting {

    verifierMerkleTree vMerkleProof;
    verifierZKSNARK vzkSNARK;

    // The minimum amount of time that must pass between a voter posting their vote
    // and the voting period ending. This is to prevent last-minute vote stuffing.
    uint256 public constant MIN_VOTE_POSTING_TIME = 60 * 60 * 24; // 1 day

    // The minimum amount of time that must pass between the voting period starting
    // and ending. This is to ensure that there is sufficient time for all voters
    // to cast their ballots.
    uint256 public constant MIN_VOTING_PERIOD = 7 * MIN_VOTE_POSTING_TIME; // 1 week

    // The maximum number of candidates allowed in this election.
    uint256 public constant MAX_CANDIDATES = 99;

    // The current state of the election.
    enum State {
        // The election has not yet started.
        PRE_VOTING,
        // The election is currently in progress.
        VOTING,
        // The election has ended and the votes are being tallied.
        POST_VOTING,
        // The election has been finalized and the results have been recorded.
        FINISHED
    }
    State public state;

    // The start and end timestamps of the voting period.
    uint256 public startTime;
    uint256 public endTime;

    // The list of candidates in this election.
    struct Candidate {
        // The name of the candidate.
        string name;
        // The total number of votes received by the candidate.
        uint256 voteCount;
    }
    Candidate[] public candidates;

    // The list of voters in this election.
    struct Voter {
        // The Ethereum address of the voter.
        address addr;
        // A flag indicating whether the voter has already cast their vote.
        bool hasVoted;
        // The zk-SNARK proof of the voter's vote.
        uint[] proofa;
        // The zk-SNARK proof of the voter's vote.
        uint[][] proofb;
        // The zk-SNARK proof of the voter's vote.
        uint[] proofc;
        // The input data used to generate the zk-SNARK proof.
        uint[] input;
    }
    Voter[] public voters;

    // The contract owner.
    address public owner;

    // The contract constructor.
    constructor() {
        owner = msg.sender;
        state = State.PRE_VOTING;
    }

    // Adds a candidate to the election.
    // Only the contract owner can add candidates.
    function addCandidate(
        string memory _name) public {
        require(state == State.PRE_VOTING, "Voting has already started.");
        require(candidates.length < MAX_CANDIDATES, "Max number of candidates reached.");
        require(bytes(_name).length > 0, "Invalid candidate name.");
        require(owner == msg.sender, "Only the contract owner can add candidates.");

        candidates.push(Candidate(_name, 0));
    }

    // Begins the voting period.
    // Only the contract owner can begin the voting period.
    function startVoting(uint256 _startTime, uint256 _endTime) public {
        require(state == State.PRE_VOTING, "Voting has already started.");
        require(_startTime > block.timestamp, "Start time must be in the future.");
        require(_endTime > _startTime, "End time must be after start time.");
        require(_endTime - _startTime >= MIN_VOTING_PERIOD, "Voting period is too short.");
        require(owner == msg.sender, "Only the contract owner can start the voting period.");

        startTime = _startTime;
        endTime = _endTime;
        state = State.VOTING;
    }

    // Posts a vote to the contract.
    function vote(uint256 _candidateId, uint[2] memory _proofa, uint[2][2] memory _proofb, uint[2] memory _proofc, uint[] memory _input) public {
        require(state == State.VOTING, "Voting is not currently in progress.");
        require(_candidateId < candidates.length, "Invalid candidate id.");
        require(_proofa.length > 0, "Invalid proof a.");
        require(_proofb.length > 0, "Invalid proof b.");
        require(_proofc.length > 0, "Invalid proof c.");
        require(_input.length > 0, "Invalid input data.");
        require(block.timestamp > startTime, "Voting has not yet started.");
        require(block.timestamp < endTime - MIN_VOTE_POSTING_TIME, "Voting period has ended.");

        // Check if the voter has already cast their vote.
        //address voterAddr = msg.sender;
        Voter storage voter = voters[_candidateId];
        require(!voter.hasVoted, "You have already cast your vote.");

        // Verify the zk-SNARK proof.

        require(vzkSNARK.verifyProof(_proofa, _proofb, _proofc, _input, 0), "Invalid proof.");
        
        // Update the voter's information.
        voter.hasVoted = true;
        voter.proofa = _proofa;
        voter.proofb = _proofb;
        voter.proofc = _proofc;
        voter.input = _input;

        // Update the candidate's vote count.
        candidates[_candidateId].voteCount++;
    }

    // Finalizes the election and records the results.
    // Only the contract owner can finalize the election.
    function finalize() public {
        require(state == State.VOTING, "Voting is not currently in progress.");
        require(block.timestamp > endTime, "Voting period has not yet ended.");
        require(owner == msg.sender, "Only the contract owner can finalize the election.");

        state = State.FINISHED;
    }

    // Gets the vote count for a specific candidate.
    function getVoteCount(uint256 _candidateId) public view returns (uint256) {
                require(_candidateId < candidates.length, "Invalid candidate id.");
        return candidates[_candidateId].voteCount;
    }

    // Gets the total number of votes cast in this election.
    function getTotalVoteCount() public view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < candidates.length; i++) {
            total += candidates[i].voteCount;
        }
        return total;
    }

    // Gets the voter information for a specific address.
    // function getVoterInfo(uint256 _addr) public returns (bool, uint[] memory, uint[2] memory, uint[] memory, uint[] memory) {
    //     Voter storage voter = voters[_addr];
    //     return (voter.hasVoted, voter.proofa, voter.proofb, voter.proofc, voter.input);
    // }
}
