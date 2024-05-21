# lab-4-iron-hack
Laboratorio: Implementación y pruebas de seguridad en aplicaciones.

# Scenario 1: Pseudo-Code for Authentication System
## Pseudo-Code Example:

```
FUNCTION authenticateUser(username, password):
  QUERY database WITH username AND password
  IF found RETURN True
  ELSE RETURN False

```

### Security Scanning Simulation

### SAST

1.- Inyección SQL: Se observan consultas hacía la bd sql directamente, es decir usando los parametros de entrada. Si los parametros: usuario y password no se validan o "sanitizan" puede ser suceptibles a inyección SQL.
```
String sql = "SELECT user, password, isActive FROM users WHERE username = ? AND password = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();

```

Podemos hacer valisación o sanitización de inputs:
```
if (username == null || username.isEmpty() || !username.matches("^[a-zA-Z0-9_]+$")) {
    throw new BadRequestException("ErroCode: 902");
}

if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
    throw new BadRequestException("ErrorCode 903");
}
```

2.- Almacenamiento de Contraseñas: Se infiere que el campo contraseña, se encuentra almacenado en texto plano, es decir, tal cual lo ingresa un usuario, tal cual se busca en base de datos. Lo cual es una mala práctica y potencialmente peligroso a usuarios mal intencionados. Lo ideal es solo comprar el hash de una contraseña y si se almacena, utilizar un algormitmo de cifrado fuerte.

```
// Se almacenará cifrado en hash....
String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

// Se comparará solo los chash más no el valor
if (BCrypt.checkpw(password, storedHashedPassword)) {
    return true;
}
```

3.- Rate limiter en login:  No se observa un menejo apropiado de los intentos de inicio de sesión, es decir, un utacante, podría estar lanzando un ataque por diccionario intentando "adivinar" un password o username a fin de poder tener un acceso no autorizado a una cuenta. Se recomienda manejar un rate limiter para intentos fallidos de inicio de sesión, se recomianda usar cache para validar si una dirección ip o un usuario lleva un determinado número de intentos, si supera el umbral hacer un banneo  temporal (o indefinido) de tal manera de desalentar a un atacante e impledir continua un brute force. Adicional a esto, se recomienda sanitizar los datos de entrada así como implementar algún tipo de recaptcha.

```
// podemos validar en cache si ya tiene intentos fallidos de login
int attempts = getFailedAttempts(username);
if (attempts >= MAX_ATTEMPTS) {
    throw new AccountLockedException("ErrorCode:901");
}

// si el login es exitoso, limpiamos intentos, si no se incrementa el contados.
if (authenticate(username, password)) {
    resetFailedAttempts(username);
} else {
    incrementFailedAttempts(username);
}
```

Manejo de Errores Genéricos: En el escenario se observa un manejo de error  muy generico que no da información técnica para poder diagnosticar algún error en el sistema, lo ideal es crear una clase de error-codes donde solo el equipo de desarrollo y production support tengan la tabla de errores, y el sistema cuando lance un error, sea un error code que no de información detallada de "x" error a un atacante.

### DAST

Adicional a los escaneos SAST, podemos reforzar la seguridad de nuestra aplicación con lo siguiente:

1.- Ejecución de pruebas de pen test. Donde se realizan pruebas no intrusivas a una aplicación, y se pueden detectar vulnerabilidades de inyección sql, fuerza bruta, posible enumeración de usuarios,  estructura de politica de contraseñas expuestas etc, entre otros puntos, igual se scanea el transporte, que sea seguro preferentemente sobre https, certificados fuertes, DAST puede ser configurado para ejecutar pasos acorde a cada proyecto y herramienta utilizada.

# Scenario 2: JWT Authentication Schema
## Design Outline:

```
DEFINE FUNCTION generateJWT(userCredentials):
  IF validateCredentials(userCredentials):
    SET tokenExpiration = currentTime + 3600 // Token expires in one hour
    RETURN encrypt(userCredentials + tokenExpiration, secretKey)
  ELSE:
    RETURN error
```

  1.- Generación de JWT insegura. No se sigue un estandar para generar un JWT de manera segura, se debe seguir la estructura: header, payload y firma.
```
  import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public String generateJWT(UserCredentials userCredentials) {
    if (validateCredentials(userCredentials)) {
        long expirationTime = System.currentTimeMillis() + 3600 * 1000; // tiempo de vida del token.
        return Jwts.builder()
            .setSubject(userCredentials.getUsername())
            .setExpiration(new Date(expirationTime))
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    } else {
        throw new BadRequestException("Login error code 805");
    }
}
```

  2.- Errores generados de manera muy generica, no dan información que determine que ocurrio. Se puede hacer uso de respuestas de eror que indiquen un error code que permita determinar que sucedio, sin dar información a detalle de error.
  
```
 if (!validateCredentials(userCredentials)) {
    log.error("Invalid credentials for user: " + userCredentials.getUsername());
    throw new BadRequestException("Loging error: 805");
}
```
  
  3.- Al cifrar con secret la el JWT, este no debe vivir en la aplicación, debe resguardarse en un lugar seguro, por ejemplo un secret manager donde solo la app tenga permiso de lectura.
<img width="1180" alt="secret" src="https://github.com/ventura-gorostieta/lab-4-iron-hack/assets/97199485/76c0eb9a-0252-4111-b150-c64e735a964d">

  
  4.- La expiración del token es fija, esta debería ser configurable, según el dominio de negocio o requerimiento, ya que no en todos los contextos de seguridad se debe tener el mismo tiempo de vida de un token.
![jwt-example](https://github.com/ventura-gorostieta/lab-4-iron-hack/assets/97199485/5003a381-f51b-4f81-926f-7500dce5c75e)


5.- Otra opcipon que abstrae el uso de JWT, es AWS Cognito, donde se configura un pool de usuarios y este pool se configura, el tiempo de vida del token, clientes de aplicación que se pueden conectar al pool, las caracteristicas usario, el tipo de login, entre muchas más configuraciones que podemos hacer uso y poder sanitizar correctamente el uso de JWT.

![aws cognito](https://github.com/ventura-gorostieta/lab-4-iron-hack/assets/97199485/dd8f033e-5b1f-44ef-a834-5dde5c2b8823)

login example:

![login-schema](https://github.com/ventura-gorostieta/lab-4-iron-hack/assets/97199485/c3ba317c-5adf-4313-9fdb-6c4545cf20c7)


### DAST

1.- Para las pruebas DAST, se puede realizar intentos de manipular el token y firma. Utilizar un mismo token que ya se encuentre expirado o "quemado". Esto podrá garantizar que la appa gestiona correctamente el uso de los jwt.

2.- Si optamos por secret manager, se puede configurar una rotación automatica de secret a fin de garantizar mayor seguridad al momento de generar los jwt para determinada aplicación.

3.- Ejecutar scaneos de de vulnerabilidades y detectar librerías vulnerables en cuanto a implementación de Jwt custom.

# Scenario 3: Secure Data Communication Plan
## Outline for Data Protection:


```
PLAN secureDataCommunication:
  IMPLEMENT SSL/TLS for all data in transit
  USE encrypted storage solutions for data at rest
  ENSURE all data exchanges comply with HTTPS protocols

```

1.- Certificados SSL/TLS: Implementar certificados que vengan de uuna certificadora, evitar el uso de certificados autofirmados. Mantener un control sobre la fecha de vencimiento de los certificados, esto para prevenir sean caducados.

2.- Configuración de SSL/TLS: Si se usan servidores web,  se debe forzar siempre la conexión sobre https, en dado caso de que se exponga algo pro el fuerto 80, forzar un redirect hacía el puerto seguro que pasa por https. Forzar o solo permitir conexiones TLS 1.2 o superios.

3.- Pruebas de seguridad: se recomienda hacer pruebas de intento de roper los certificados y validar que el númeto de bits de cifrado sea el correcto, se recomienda usar 4096 bits con RSA.

4.- Cifrado de datos en reposo: Se debe habilitar el cifrado de datos en reposo acorde al motor de base de datos o tipo de almacenamiento, por ejemplo en mogo se puede habilitar AES para cifrado, en solucione sde almacenamiento cloud como s3, EBS, ERDS,etc; se puede habilitar el cifrado en transito y en reposo.

