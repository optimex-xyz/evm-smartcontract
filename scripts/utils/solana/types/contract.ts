/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/bitfi_sol_smartcontract.json`.
 */
export type BitfiSolSmartcontract = {
  address: "E2pt2s1vZjgf1eBzWhe69qDWawdFKD2u4FbLEFijSMJP";
  metadata: {
    name: "bitfiSolSmartcontract";
    version: "0.1.0";
    spec: "0.1.0";
    description: "Created with Anchor";
  };
  instructions: [
    {
      name: "addOrRemoveOperator";
      docs: [
        "@notice Add or remove an operator\n        @dev\n        - Requirements:\n            - Caller must be authorized\n        - Params:\n            - operator             The operator to add or remove\n            - is_add               Whether to add or remove the operator",
      ];
      discriminator: [242, 151, 243, 85, 157, 174, 36, 182];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "config";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
      ];
      args: [
        {
          name: "operator";
          type: "pubkey";
        },
        {
          name: "isAdd";
          type: "bool";
        },
      ];
    },
    {
      name: "addOrUpdateWhitelist";
      docs: [
        "@notice Add or update whitelist token setup\n      @dev\n      - Requirements:\n           - Caller must be authorized as an operator\n      - Params:\n           - amount               Amount of the whitelist token",
      ];
      discriminator: [37, 38, 2, 162, 195, 182, 21, 30];
      accounts: [
        {
          name: "operator";
          writable: true;
          signer: true;
        },
        {
          name: "config";
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
        {
          name: "whitelistToken";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [119, 104, 105, 116, 101, 108, 105, 115, 116];
              },
              {
                kind: "account";
                path: "token";
              },
            ];
          };
        },
        {
          name: "token";
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [
        {
          name: "amount";
          type: "u64";
        },
      ];
    },
    {
      name: "claim";
      docs: [
        "@notice Claim the deposited amount after the timeout\n        @dev\n        - Requirements:\n            - Caller must be authorized:\n                - Caller can be anyone\n            - Available to call when `timestamp > timeout`\n        - Params:\n            - claim_args           Arguments required for the claim",
      ];
      discriminator: [62, 198, 214, 193, 213, 159, 108, 210];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "userAccount";
          writable: true;
        },
        {
          name: "nonceCheckAccount";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [110, 111, 110, 99, 101];
              },
              {
                kind: "account";
                path: "user_trade_detail.user_ephemeral_pubkey";
                account: "tradeDetail";
              },
            ];
          };
        },
        {
          name: "userTradeDetail";
          writable: true;
        },
        {
          name: "vault";
          writable: true;
        },
        {
          name: "refundAccount";
          writable: true;
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [
        {
          name: "claimArgs";
          type: {
            defined: {
              name: "claimArgs";
            };
          };
        },
      ];
    },
    {
      name: "closeFinishedTrade";
      docs: [
        "@notice Close the finished trade (settled or claimed)\n        to reclaim some rent fee for users\n        @dev\n        - Requirements:\n            - Caller can be anyone\n            - Available to call when `timestamp > timeout + close_wait_duration`",
      ];
      discriminator: [176, 51, 115, 198, 119, 249, 227, 63];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "userAccount";
          writable: true;
        },
        {
          name: "userTradeDetail";
          writable: true;
        },
        {
          name: "vault";
          writable: true;
        },
        {
          name: "config";
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
        {
          name: "vaultTokenAccount";
          writable: true;
          optional: true;
        },
        {
          name: "tokenProgram";
          address: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        },
      ];
      args: [
        {
          name: "closeFinishedTradeArgs";
          type: {
            defined: {
              name: "closeFinishedTradeArgs";
            };
          };
        },
      ];
    },
    {
      name: "closePaymentReceipt";
      docs: [
        "@notice Close the payment receipt\n        to reclaim rent fee for payment receipt\n        @dev\n        - Requirements:\n            - Caller can be anyone\n            - Available to call when `timestamp > payment_time + close_wait_duration`",
      ];
      discriminator: [192, 42, 180, 252, 51, 166, 11, 158];
      accounts: [
        {
          name: "signer";
          docs: [
            "The signer account, which must be mutable, and must be the same as the user account.",
          ];
          writable: true;
          signer: true;
        },
        {
          name: "paymentReceipt";
          writable: true;
        },
        {
          name: "config";
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [];
    },
    {
      name: "deposit";
      docs: [
        "@notice Handles the deposit of either tokens or SOL into the vault\n        @dev\n        - Requirements:\n            - Available to call when `timestamp <= timeout`\n        - Params:\n            - deposit_args         Arguments required for the deposit",
      ];
      discriminator: [242, 35, 198, 137, 82, 225, 242, 182];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "userTradeDetail";
          writable: true;
        },
        {
          name: "ephemeralAccount";
          writable: true;
          signer: true;
        },
        {
          name: "nonceCheckAccount";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [110, 111, 110, 99, 101];
              },
              {
                kind: "account";
                path: "ephemeralAccount";
              },
            ];
          };
        },
        {
          name: "vault";
          writable: true;
        },
        {
          name: "whitelistToken";
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [
        {
          name: "depositArgs";
          type: {
            defined: {
              name: "depositArgs";
            };
          };
        },
      ];
    },
    {
      name: "init";
      docs: [
        "@notice Initializes the vault and protocol accounts\n        @dev\n        - Requirements:\n            - Caller must be authorized\n        - Params:\n            - init_args            Arguments required for initialization (currently empty)",
      ];
      discriminator: [220, 59, 207, 236, 108, 250, 47, 100];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "vault";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [118, 97, 117, 108, 116];
              },
            ];
          };
        },
        {
          name: "protocol";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [112, 114, 111, 116, 111, 99, 111, 108];
              },
            ];
          };
        },
        {
          name: "config";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
        {
          name: "program";
          address: "E2pt2s1vZjgf1eBzWhe69qDWawdFKD2u4FbLEFijSMJP";
        },
        {
          name: "programData";
        },
      ];
      args: [
        {
          name: "initArgs";
          type: {
            defined: {
              name: "initArgs";
            };
          };
        },
      ];
    },
    {
      name: "payment";
      docs: [
        "@notice Handles the payment process\n        @dev\n        - Requirements:\n            - Caller must be authorized\n        - Params:\n            - deposit_args         Arguments required for the payment",
      ];
      discriminator: [156, 226, 80, 91, 104, 252, 49, 142];
      accounts: [
        {
          name: "signer";
          docs: ["The signer account, which must be mutable."];
          writable: true;
          signer: true;
        },
        {
          name: "toUser";
          docs: ["The account to which the payment will be sent."];
          writable: true;
        },
        {
          name: "protocol";
          docs: [
            "The protocol account to which the protocol fee will be sent.",
          ];
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [112, 114, 111, 116, 111, 99, 111, 108];
              },
            ];
          };
        },
        {
          name: "whitelistToken";
        },
        {
          name: "paymentReceipt";
          writable: true;
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [
        {
          name: "paymentArgs";
          type: {
            defined: {
              name: "paymentArgs";
            };
          };
        },
      ];
    },
    {
      name: "removeWhitelist";
      docs: [
        "@notice Remove whitelist token setup\n      @dev\n      - Requirements:\n           - Caller must be authorized as an operator",
      ];
      discriminator: [148, 244, 73, 234, 131, 55, 247, 90];
      accounts: [
        {
          name: "operator";
          writable: true;
          signer: true;
        },
        {
          name: "config";
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
        {
          name: "whitelistToken";
          writable: true;
        },
        {
          name: "token";
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [];
    },
    {
      name: "setCloseWaitDuration";
      docs: [
        "@notice Set the duration for closing a finished trade\n        @dev\n        - Requirements:\n            - Caller must be authorized as an operator\n        - Params:\n            - duration             The duration for closing a finished trade",
      ];
      discriminator: [14, 233, 71, 143, 55, 182, 177, 231];
      accounts: [
        {
          name: "operator";
          writable: true;
          signer: true;
        },
        {
          name: "config";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [99, 111, 110, 102, 105, 103];
              },
            ];
          };
        },
      ];
      args: [
        {
          name: "setCloseWaitDurationArgs";
          type: {
            defined: {
              name: "setCloseWaitDurationArgs";
            };
          };
        },
      ];
    },
    {
      name: "setTotalFee";
      docs: [
        "@notice Sets the protocol fee for a trade\n        @dev\n        - Requirements:\n            - Signature that signed by MPC\n        - Params:\n            - set_total_fee Arguments required for setting the total fee",
      ];
      discriminator: [4, 250, 240, 112, 5, 249, 79, 109];
      accounts: [
        {
          name: "signer";
          docs: ["The signer account, which must be mutable and authorized"];
          writable: true;
          signer: true;
        },
        {
          name: "userTradeDetail";
          docs: ["The user trade detail account"];
          writable: true;
        },
      ];
      args: [
        {
          name: "setTotalFeeArgs";
          type: {
            defined: {
              name: "setTotalFeeArgs";
            };
          };
        },
      ];
    },
    {
      name: "settlement";
      docs: [
        "@notice Transfer `amount` to `toAddress` to finalize the `tradeId`\n        @dev\n        - Requirements:\n            - Caller must be authorized:\n                - Signature that signed by MPC\n                - Signature that signed by the user\n            - Available to call when `timestamp <= timeout`\n        - Params:\n            - payment_args         Arguments required for the settlement",
      ];
      discriminator: [128, 21, 174, 60, 47, 86, 130, 108];
      accounts: [
        {
          name: "signer";
          writable: true;
          signer: true;
        },
        {
          name: "userAccount";
          writable: true;
        },
        {
          name: "userEphemeralAccount";
          signer: true;
        },
        {
          name: "userTradeDetail";
          writable: true;
        },
        {
          name: "nonceCheckAccount";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [110, 111, 110, 99, 101];
              },
              {
                kind: "account";
                path: "userEphemeralAccount";
              },
            ];
          };
        },
        {
          name: "vault";
          writable: true;
        },
        {
          name: "refundAccount";
          writable: true;
        },
        {
          name: "protocol";
          writable: true;
          pda: {
            seeds: [
              {
                kind: "const";
                value: [112, 114, 111, 116, 111, 99, 111, 108];
              },
            ];
          };
        },
        {
          name: "pmm";
          writable: true;
        },
        {
          name: "systemProgram";
          address: "11111111111111111111111111111111";
        },
      ];
      args: [
        {
          name: "paymentArgs";
          type: {
            defined: {
              name: "settlementArgs";
            };
          };
        },
      ];
    },
  ];
  accounts: [
    {
      name: "config";
      discriminator: [155, 12, 170, 224, 30, 250, 204, 130];
    },
    {
      name: "nonceCheckAccount";
      discriminator: [191, 217, 36, 242, 192, 98, 193, 237];
    },
    {
      name: "paymentReceipt";
      discriminator: [168, 198, 209, 4, 60, 235, 126, 109];
    },
    {
      name: "tradeDetail";
      discriminator: [241, 58, 83, 75, 150, 155, 85, 205];
    },
    {
      name: "tradeVault";
      discriminator: [233, 99, 74, 124, 61, 226, 5, 175];
    },
    {
      name: "whitelistToken";
      discriminator: [179, 42, 207, 134, 155, 42, 77, 114];
    },
  ];
  events: [
    {
      name: "claimed";
      discriminator: [217, 192, 123, 72, 108, 150, 248, 33];
    },
    {
      name: "deposited";
      discriminator: [111, 141, 26, 45, 161, 35, 100, 57];
    },
    {
      name: "paymentTransferred";
      discriminator: [206, 116, 224, 136, 100, 105, 246, 173];
    },
    {
      name: "settled";
      discriminator: [232, 210, 40, 17, 142, 124, 145, 238];
    },
  ];
  errors: [
    {
      code: 6000;
      name: "invalidTradeId";
    },
    {
      code: 6001;
      name: "invalidTimeout";
    },
    {
      code: 6002;
      name: "unauthorized";
    },
    {
      code: 6003;
      name: "invalidPublicKey";
    },
    {
      code: 6004;
      name: "depositZeroAmount";
    },
    {
      code: 6005;
      name: "invalidAmount";
    },
    {
      code: 6006;
      name: "invalidMintKey";
    },
    {
      code: 6007;
      name: "invalidSourceAta";
    },
    {
      code: 6008;
      name: "invalidDestinationAta";
    },
    {
      code: 6009;
      name: "timeOut";
    },
    {
      code: 6010;
      name: "invalidRefundPubkey";
    },
    {
      code: 6011;
      name: "cLaimNotAvailable";
    },
    {
      code: 6012;
      name: "deadlineExceeded";
    },
    {
      code: 6013;
      name: "invalidUserAccount";
    },
    {
      code: 6014;
      name: "nonceAccountBeingUsed";
    },
    {
      code: 6015;
      name: "operatorAlreadyExists";
    },
    {
      code: 6016;
      name: "operatorNotFound";
    },
    {
      code: 6017;
      name: "operatorLimitReached";
    },
    {
      code: 6018;
      name: "notWhitelistedToken";
    },
    {
      code: 6019;
      name: "invalidTradeStatus";
    },
    {
      code: 6020;
      name: "closeNotAvailable";
    },
    {
      code: 6021;
      name: "invalidTokenAccount";
    },
  ];
  types: [
    {
      name: "claimArgs";
      docs: ["Arguments required for the claim function"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            docs: ["Unique identifier for the trade"];
            type: {
              array: ["u8", 32];
            };
          },
        ];
      };
    },
    {
      name: "claimed";
      docs: [
        "- @dev Event emitted when a user successfully claims the deposit after timeout\n    - Related function: claim()",
      ];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "toPubkey";
            type: "pubkey";
          },
          {
            name: "operator";
            type: "pubkey";
          },
          {
            name: "amount";
            type: "u64";
          },
        ];
      };
    },
    {
      name: "closeFinishedTradeArgs";
      docs: ["Arguments required for the deposit function"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
        ];
      };
    },
    {
      name: "config";
      type: {
        kind: "struct";
        fields: [
          {
            name: "reserve";
            type: {
              array: ["u128", 7];
            };
          },
          {
            name: "admin";
            type: "pubkey";
          },
          {
            name: "closeTradeDuration";
            type: "u64";
          },
          {
            name: "closePaymentDuration";
            type: "u64";
          },
          {
            name: "operators";
            type: {
              vec: "pubkey";
            };
          },
        ];
      };
    },
    {
      name: "depositArgs";
      docs: ["Arguments required for the deposit function"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "input";
            docs: ["Input trade information"];
            type: {
              defined: {
                name: "tradeInput";
              };
            };
          },
          {
            name: "data";
            docs: ["Detailed trade data"];
            type: {
              defined: {
                name: "tradeDetailInput";
              };
            };
          },
          {
            name: "tradeId";
            docs: ["Unique identifier for the trade"];
            type: {
              array: ["u8", 32];
            };
          },
        ];
      };
    },
    {
      name: "deposited";
      docs: [
        "- @dev Event emitted when a user successfully deposits tokens or SOL\n    - Related function: deposit()",
      ];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "fromPubkey";
            type: "pubkey";
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "amount";
            type: "u64";
          },
          {
            name: "vault";
            type: "pubkey";
          },
        ];
      };
    },
    {
      name: "initArgs";
      docs: ["Arguments required for the init function"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "admin";
            docs: [
              "The admin of the protocol. If this is not none, the instruction will set the admin",
            ];
            type: {
              option: "pubkey";
            };
          },
        ];
      };
    },
    {
      name: "nonceCheckAccount";
      type: {
        kind: "struct";
        fields: [];
      };
    },
    {
      name: "paymentArgs";
      docs: ["Arguments for the payment instruction."];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            docs: ["Unique identifier for the trade."];
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "token";
            docs: ["Optional token public key for SPL token payments."];
            type: {
              option: "pubkey";
            };
          },
          {
            name: "amount";
            docs: ["Amount to be transferred."];
            type: "u64";
          },
          {
            name: "totalFee";
            docs: ["Protocol fee to be deducted from the amount."];
            type: "u64";
          },
          {
            name: "deadline";
            docs: ["Deadline for the payment transaction."];
            type: "i64";
          },
        ];
      };
    },
    {
      name: "paymentReceipt";
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "fromPubkey";
            type: "pubkey";
          },
          {
            name: "toPubkey";
            type: "pubkey";
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "paymentAmount";
            type: "u64";
          },
          {
            name: "totalFee";
            type: "u64";
          },
          {
            name: "paymentTime";
            type: "u64";
          },
          {
            name: "reserve";
            type: {
              array: ["u128", 8];
            };
          },
        ];
      };
    },
    {
      name: "paymentTransferred";
      docs: [
        "- @dev Event emitted when PMM successfully settle the payment\n    - Related function: payment();",
      ];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "fromPubkey";
            type: "pubkey";
          },
          {
            name: "toPubkey";
            type: "pubkey";
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "paymentAmount";
            type: "u64";
          },
          {
            name: "totalFee";
            type: "u64";
          },
          {
            name: "protocol";
            type: "pubkey";
          },
        ];
      };
    },
    {
      name: "setCloseWaitDurationArgs";
      type: {
        kind: "struct";
        fields: [
          {
            name: "closeTradeDuration";
            type: {
              option: "u64";
            };
          },
          {
            name: "closePaymentDuration";
            type: {
              option: "u64";
            };
          },
        ];
      };
    },
    {
      name: "setTotalFeeArgs";
      docs: ["Arguments required for setting the protocol fee"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            docs: ["Unique identifier for the trade"];
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "amount";
            docs: ["Amount of the protocol fee"];
            type: "u64";
          },
        ];
      };
    },
    {
      name: "settled";
      docs: [
        "- @dev Event emitted when MPC successfully settles the trade\n    - Related function: settlement()",
      ];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "operator";
            type: "pubkey";
          },
          {
            name: "toPubkey";
            type: "pubkey";
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "settlementAmount";
            type: "u64";
          },
          {
            name: "totalFee";
            type: "u64";
          },
          {
            name: "vault";
            type: "pubkey";
          },
          {
            name: "protocol";
            type: "pubkey";
          },
        ];
      };
    },
    {
      name: "settlementArgs";
      docs: ["Arguments required for the settlement function"];
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            docs: ["Unique identifier for the trade"];
            type: {
              array: ["u8", 32];
            };
          },
        ];
      };
    },
    {
      name: "tradeDetail";
      type: {
        kind: "struct";
        fields: [
          {
            name: "tradeId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "userPubkey";
            type: "pubkey";
          },
          {
            name: "token";
            type: {
              option: "pubkey";
            };
          },
          {
            name: "amount";
            type: "u64";
          },
          {
            name: "timeout";
            type: "i64";
          },
          {
            name: "mpcPubkey";
            type: "pubkey";
          },
          {
            name: "userEphemeralPubkey";
            type: "pubkey";
          },
          {
            name: "refundPubkey";
            type: "pubkey";
          },
          {
            name: "totalFee";
            type: {
              option: "u64";
            };
          },
          {
            name: "status";
            type: {
              defined: {
                name: "tradeStatus";
              };
            };
          },
          {
            name: "settledPmm";
            type: "pubkey";
          },
          {
            name: "reserve";
            type: {
              array: ["u128", 8];
            };
          },
        ];
      };
    },
    {
      name: "tradeDetailInput";
      type: {
        kind: "struct";
        fields: [
          {
            name: "timeout";
            type: "i64";
          },
          {
            name: "mpcPubkey";
            type: "pubkey";
          },
          {
            name: "refundPubkey";
            type: "pubkey";
          },
        ];
      };
    },
    {
      name: "tradeInfo";
      type: {
        kind: "struct";
        fields: [
          {
            name: "amountIn";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "fromChain";
            type: {
              array: ["bytes", 3];
            };
          },
          {
            name: "toChain";
            type: {
              array: ["bytes", 3];
            };
          },
        ];
      };
    },
    {
      name: "tradeInput";
      type: {
        kind: "struct";
        fields: [
          {
            name: "sessionId";
            type: {
              array: ["u8", 32];
            };
          },
          {
            name: "solver";
            type: {
              array: ["u8", 20];
            };
          },
          {
            name: "tradeInfo";
            type: {
              defined: {
                name: "tradeInfo";
              };
            };
          },
        ];
      };
    },
    {
      name: "tradeStatus";
      type: {
        kind: "enum";
        variants: [
          {
            name: "deposited";
          },
          {
            name: "settled";
          },
          {
            name: "claimed";
          },
        ];
      };
    },
    {
      name: "tradeVault";
      type: {
        kind: "struct";
        fields: [];
      };
    },
    {
      name: "whitelistToken";
      type: {
        kind: "struct";
        fields: [
          {
            name: "token";
            type: "pubkey";
          },
          {
            name: "amount";
            type: "u64";
          },
          {
            name: "reserve";
            type: {
              array: ["u128", 4];
            };
          },
        ];
      };
    },
  ];
};
