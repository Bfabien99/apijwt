<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManager;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

class ApiController extends AbstractController
{
    private $em;
    private $userRepository;
    private $SECRET = "L3_m0nd3_p4r5_3n_C0u1ll3";

    public function __construct(UserRepository $userRepository, EntityManagerInterface $em){
        $this->userRepository = $userRepository;
        $this->em = $em;
    }

    ###################################
    ####### GENERER UN TOKEN ##########
    ###################################
    private function generateToken(?array $Payload, $validity = 86400): string
    {

        ## Création d'un token JWT
        // Ajouter une date d'expiration
        if($validity > 0){
            $now = new \DateTime();
            $expiration = $now->getTimestamp() + $validity;
            $Payload['iat'] = $now->getTimestamp();
            $Payload['exp'] = $expiration;
        }

        // Le Header par défaut
        $Header = [
            "alg" => "HS256",
            "typ" => "JWT"
        ];

        function sanitazeBase(string $baseEncode){
            return str_replace(['+','/','='],['-','_',''],$baseEncode);
        }

        //On récupère le payload
        //...

        //On transforme en JSON puis on encode en base64 le Header et le Payload
        $baseHeader = sanitazeBase(base64_encode(json_encode($Header)));
        $basePayload = sanitazeBase(base64_encode(json_encode($Payload)));

        #On génère la signature
        //On encode notre SECRET
        $secret = base64_encode($this->SECRET);

        $hashSignature = hash_hmac('sha256', $baseHeader . '.' . $basePayload, $secret, true);

        $signature = sanitazeBase(base64_encode($hashSignature));

        #On Crée le Token
        $jwt = $baseHeader . '.' . $basePayload . '.' . $signature;

        return $jwt;
    }

    ##############################################
    ####### RECUPERER LE HEADER DU TOKEN #########
    ##############################################
    private function getHeader(string $token)
    {
        // explode du token
        $explodeToken = explode('.', $token);

        //On décode le Header
        $Header = json_decode(base64_decode($explodeToken[0]), true);

        return $Header;
    }

    ################################################
    ####### RECUPERER LE PAYLOAD DU TOKEN ##########
    ################################################
    private function getPayload(string $token)
    {
        // explode du token
        $explodeToken = explode('.', $token);

        //On décode le Payload
        $Payload = json_decode(base64_decode($explodeToken[1]), true);

        return $Payload;
    }

    ########################################
    ####### VERIFICATION DU TOKEN ##########
    ########################################
    private function verifyToken(string $token):bool
    {
        //On récupère le Header et le Payload
        $Header = $this->getHeader($token);
        $Payload = $this->getPayload($token);
        
        //On génère un token de vérification
        $verifToken = $this->generateToken($Payload, 0);

        return $token === $verifToken;
    }

    ####################################################
    #### VERIFICATION LA DATE D'EXPIRATION DU TOKEN ####
    ####################################################
    private function isExpired(string $token):bool
    {
        $payload = $this->getPayload($token);
        $now = new \DateTime();

        return $payload['exp'] < $now->getTimestamp();
    }

    ########################################################
    #### VERIFIER QUE lE TOKEN RESPECTE LE PREG_MATCH() ####
    ########################################################
    private function isValid(string $token):bool
    {
        return preg_match('/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/', $token) === 1;
    }

    ##############################################
        ######################################
    ######### LES DIFFERENTES ROUTES ############
        ######################################
    #############################################

    ######################################
    ####### ROUTES INDEX ###
    #####################################
    #[Route('/', name: 'apiHome')]
    public function index(): JsonResponse
    {
        return $this->json([
            'message' => 'This is my fist symfony api with JWT',
        ]);
    }

    ######################################
    ####### ROUTES D'AUTHENTIFICATION ###
    #####################################
    #[Route('/auth', name: 'apiAuth')]
    public function login(): JsonResponse
    {
        if($_SERVER['REQUEST_METHOD'] == "POST"){

            ## On vérifie si le token est présent
            if(isset($_SERVER['Authorization'])){
                $token = trim($_SERVER['Authorization']);
            }
            elseif(isset($_SERVER['HTTP_AUTHORIZATION'])){
                $token = trim($_SERVER['HTTP_AUTHORIZATION']);
                $token = str_replace('Bearer ', '', $token);
            }elseif(function_exists('apache_request_headers')){
                $requestHeaders = apache_request_headers();
                if(isset($requestHeaders['Authorization'])){
                    $token = trim($requestHeaders['Authorization']);
                }
            }

            // On vérifie si le token existe
            if(!isset($token)){
                return $this->json([
                    "status" => 400,
                    "message" => "Token introuvable",
                    "data" => [],
                ]);
                exit();
            }

            // On vérifie si sa structure est valide
            if(!$this->isValid($token)){
                return $this->json([
                    "status" => 200,
                    "message" => "Token non valide!",
                    "data" => [],
                ]);
                exist();
            }

            if($this->verifyToken($token)){
                return $this->json([
                    "status" => 200,
                    "message" => "User exist",
                    "data" => [],
                ]);
            }else{
                return $this->json([
                    "status" => 403,
                    "message" => "User doesn't exist",
                    "data" => [],
                ]);
            }
            
        }
        else{
            return $this->json([
                "status" => 405,
                "message" => "Method not allowed",
                "data" => [],
            ]);
        }
    }

    ######################################
    ####### ROUTES D'INSCRIPTION #########
    ######################################
    #[Route('/register', name: 'apiRegister')]
    public function register(): JsonResponse
    {   
        $requestBody = json_decode(file_get_contents('php://input'), TRUE);

        // On retire le password du Payload
        unset($requestBody['password']);

        // On génère le token
        $jwt = $this->generateToken($requestBody);

        if($_SERVER['REQUEST_METHOD'] == "POST"){
            return $this->json([
                "status" => 201,
                "message" => "data saved !",
                "data" => $requestBody,
                "jwt" =>  $jwt
            ]);
        }else{
            return $this->json([
                "status" => 405,
                "message" => "Method not allowed",
                "data" => [],
            ]);
        }

        
    }
}
