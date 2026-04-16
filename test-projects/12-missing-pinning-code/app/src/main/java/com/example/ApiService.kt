import retrofit2.http.GET

interface ApiService {
    @GET("https://api.example.com/data")  // домен из network_security_config.xml с pin-set
    suspend fun getData(): Response<Data>
}
// CertificatePinner не используется — уязвимость
