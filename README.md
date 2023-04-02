# TUDOIGUAL

## Requisitos
- Aplicação cliente e servidor
- Aplicação cliente:
	- Apos se instalar indicar uma diretoria para os ficheiros a serem sincronizados
	- Cifrar o ficheiro imediatamente apos ser colocado na diretoria (AES)
		- Cifrar a cifra simetrica com RSA (sk do cliente)
	- Apos cifrar, calcular uma assinatura digital (guardada localmente)
	- Notificar o servidor do novo ficheiro
	- Devem ter a certeza que estao a comunicar com o servidor
		- P.e, deve haver um registo na primeira utilização
- Servidor:
	- Media as comunicações
	- Apos receber a notificação de um novo ficheiro, tentar sincronizar com os restantes clientes (caso estes estejam ligados e configurados)

## Funcionalidades básicas
- Aplicação Cliente:
	- Gera um par de chaves para criptografica de chave publica (p.e RSA). A sk é guardada no cliente (obvio)
	- Na primeira utilizacao permite o registo de um novo utilizador junto do servidor
		- Deve ser feito de forma segura (p.e Chaves efemeras Diffie-Hellman ou RSA)
	- Cifragem de ficheiros com chaves simétricas por blocos 
		- Usando a RSA do primeiro ponto
	- Ao retirar o ficheiro, deve ser feita a autenticacao do utilizador no servidor e decifrada a chave de cifra que permite decifrar o ficheiro ??
	- Ao colocar um ficheiro, é calculada a sua aassinatura digital com recurso ao servidor

## Planeamento
### Cliente
#### Setup software
- [ ] Escolher diretoria
	- [ ] Verificar que esta vazia
- [ ] Gerar sk e pk (RSA)
- [ ] Registar perante o servidor
	- [ ] Envio de username e password cifrado, e da pk

#### Uso do software
- [ ] Tentar conectar ao servidor
	- [ ] Informação cifrada
	- [ ] Caso servidor offline, ir tentando em espacos de tempo
- [ ] Detetar novo ficheiro na diretoria
	- [ ] Cifrar ficheiro
	- [ ] Enviar hash ao servidor
		- [ ] Caso servidor esteja offline, ir tentando enviar em espaços de tempo
- [ ] Detetar que ficheiro ja nao existe na diretoria
	- [ ] notificar servidor

### Servidor
#### Setup
- [ ] criar db (txt is fine) para registar os clientes e os seus ficheiros
	- [ ] conter hash do username e password
	- [ ] conter hash dos ficheiros desse utilizador
- [ ] escutar a futuras comunicações

#### Uso do software
- [ ] escutar por tentativas de ligacao
- [ ] escutar por novos ficheiros
	- [ ] apos receber, verificar se um cliente nao contem o ficheiro (hash)
		- [ ] caso nao tenha, pedir ficheiro a client1 (cifrado) e enviar ao client2 (decifrado e dps cifrado)


## Modo de implementacao
### Server
- O main vai escutar por novos clientes
	- Apos um cliente se conectar, cria uma thread especifica para esse cliente
