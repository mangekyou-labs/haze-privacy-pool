// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 14926870567675186589982956735272800186351600085374472924944635864914752391113;
    uint256 constant deltax2 = 10552064115266351327725194654700195746897702639314360876340441363411745122462;
    uint256 constant deltay1 = 15710442300473428617655881096114244855929689987446616924730223792640980932926;
    uint256 constant deltay2 = 3296537400570515276620065153621456524074557031213056502847474245300973187685;

    
    uint256 constant IC0x = 10623868524492868621422296277518859854712111566491767218363056222580522278595;
    uint256 constant IC0y = 17109987032213910115265497444825462537617542745362841345620556954929078603630;
    
    uint256 constant IC1x = 14721737243071046709655661114349690740089850679967729127187458940001167007523;
    uint256 constant IC1y = 5141059027497950428027431243533627015737682620986357259124874114905758096459;
    
    uint256 constant IC2x = 16210955710067016409501058011787206164268609159940031572785621845112876656093;
    uint256 constant IC2y = 4778476047784645046241554299948251474930400842005906739985562349455990064941;
    
    uint256 constant IC3x = 4479998621813464801613951086740204705332913270981196475037580352800517131740;
    uint256 constant IC3y = 12776205393633547061779872021468933286060200029601678111208012652095956437924;
    
    uint256 constant IC4x = 1878345246805694784524077309920937960517625809189487829172882343625024899939;
    uint256 constant IC4y = 14755650804047838982527009237859187253494545152178334132151800237841263960156;
    
    uint256 constant IC5x = 21358873073955569704992327640894687992385255466486595765263724797701313399998;
    uint256 constant IC5y = 21342818344261810058180412136264506883119943500496210704690617193865600986494;
    
    uint256 constant IC6x = 4136688444111544213340764539766929768196263973868375858429495548663622948562;
    uint256 constant IC6y = 377341238155754112232295817157327327687273340905553987303341083841786890700;
    
    uint256 constant IC7x = 14842604487858258709417141730128788416228525060561267000911554280314180138803;
    uint256 constant IC7y = 5291509194854403202138428778079495023839041460950884932288191429939989852260;
    
    uint256 constant IC8x = 19353055641880021036483499039728586814401311208649678310426037326275941754026;
    uint256 constant IC8y = 7910764232369804811272421850834318072990579106224612078443526486902158254659;
    
    uint256 constant IC9x = 2193965379042836547226239847289629680391338908951320740197356928263572972141;
    uint256 constant IC9y = 5963255948101240427705396488250125035631398658738866598421949873950559003855;
    
    uint256 constant IC10x = 2620654688324892186008621526847439019317020801195471820529644132291780077901;
    uint256 constant IC10y = 16664596233735670427114674009561408889157767946706926242710203954732697641754;
    
    uint256 constant IC11x = 2242439211777388230046170192517060577464247639009378336333540087872147035100;
    uint256 constant IC11y = 17829556488985353061906847556554735044779794442049205398702794303446937935970;
    
    uint256 constant IC12x = 17087895007536153924436135544689756363365447306317218223925206031966377692653;
    uint256 constant IC12y = 14500754131994604884390849647941501042356915753728086101248957932692079712312;
    
    uint256 constant IC13x = 21325215879004990125798239467520021913317005948296471553463994884059855351720;
    uint256 constant IC13y = 15731974940080776096415441646734739047605152126730405098876097176052458607367;
    
    uint256 constant IC14x = 14261648307976370047683834748501318739727970682744544097097622661029642602708;
    uint256 constant IC14y = 20270111923925207864425973541708407364203704524011218983428802533426475948232;
    
    uint256 constant IC15x = 1794548232832041631337252154953235954999107953749086026864236340454604536333;
    uint256 constant IC15y = 10882897783908975572957275220112562907775725949359903462759333051469070466995;
    
    uint256 constant IC16x = 3772750986118847133565222697981467234186286708081631969171110830541648046258;
    uint256 constant IC16y = 16341703526980674147440456702875150152255661601597392658501596463585673510235;
    
    uint256 constant IC17x = 4647813759777736115348936252269473266130761590777788920568152680635848558209;
    uint256 constant IC17y = 7170016638966976842724970301084576577801296325939318810362717915729361742766;
    
    uint256 constant IC18x = 6774881431812328117596079572594665687540589628894892779390557616426768984506;
    uint256 constant IC18y = 16448839952569751495778221782992892881379965095991079102316485055567183193192;
    
    uint256 constant IC19x = 14253796240111708798784188662235123912959593472239122740568974294110663528652;
    uint256 constant IC19y = 14449675925616825616809905584954269063816257133704068146398438640736656408042;
    
    uint256 constant IC20x = 15444815699476583799916443925288357355937586312299892685522127376308733818908;
    uint256 constant IC20y = 20987052747628888525421966910004134865183239090642843726650783398109090146907;
    
    uint256 constant IC21x = 21637513533011433377945161395855853198590696355365694640812825855236200463820;
    uint256 constant IC21y = 21082241947971790747174206265318443063591361819924051048726947184888555792194;
    
    uint256 constant IC22x = 6168986937298573656179913019615740881572674498670943766245557964039153126926;
    uint256 constant IC22y = 19562846275237172914576109947231179038525047495791181450005326453874800417185;
    
    uint256 constant IC23x = 13873521231795908997333667517639490379531480694219377585494982950165382337535;
    uint256 constant IC23y = 8522601793676432184038533586508711376612100053595763285612169357753337743023;
    
    uint256 constant IC24x = 19890322409638310788058393209582242201517920250421748060668032352656507249872;
    uint256 constant IC24y = 11899946769021007199291860499901540961475874373786843892508421769796715072717;
    
    uint256 constant IC25x = 308904085360264386389510288243519491825933432953589438411432237763253752920;
    uint256 constant IC25y = 18523788924200391072828496482454589922507555677101947881491712803181100038683;
    
    uint256 constant IC26x = 2060084706779599738344682818203815324126747586155514208866985250412222801896;
    uint256 constant IC26y = 12794451031524836529508947528300980872851819234065522471772403992639141313636;
    
    uint256 constant IC27x = 9121979773843451125185490354640641605317064556685156999853815084635519583872;
    uint256 constant IC27y = 8883018095661666089417086618344829758490713099046517253171291286031104086796;
    
    uint256 constant IC28x = 14853002631670636284943348275220342560667596174552145855735651870616833774051;
    uint256 constant IC28y = 13099587312493552384742754969112104070387464923673386026392909776619364103207;
    
    uint256 constant IC29x = 111172287974265813205853047887446391048076941820862630335742731276348150370;
    uint256 constant IC29y = 7227252037752600507953422581787621522505423730997571380402525771538798691889;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[29] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
