#Copyright(c) 2025 - present The Utocoin Core developers
#Distributed under the MIT software license, see the accompanying
#file COPYING or https: // opensource.org/license/mit/.

add_library(utocoin_node STATIC
  node/transaction.h
  node/transaction.cpp
)

add_library(utocoin_consensus STATIC
  script/transaction_getter.h
  script/transaction_getter.cpp
  init.h
  init.cpp
  miner-pool/miner-pool.h
)

target_link_libraries(utocoin_consensus
  PRIVATE
    utocoin_node
)

if(BUILD_KEY_TOOL)
    add_executable(utocoin-key-tool
            key-tool/key-tool.cpp
    )

    target_link_libraries(utocoin-key-tool
            bitcoin_common
            Boost::headers
            bitcoin_util
            ${Boost_LIBRARIES}
            univalue
    )
endif()