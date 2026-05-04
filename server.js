require("dotenv").config();

const express = require("express");
const cors = require("cors");
const sql = require("mssql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

let pool;

async function getPool() {
  if (!pool) {
    pool = await sql.connect(config);
    console.log("Conectado a SQL Server");
  }
  return pool;
}

sql.connect(config)
  .then(() => console.log("Conectado a SQL Server"))
  .catch(err => console.log("Error conexión:", err));

app.get("/", (req, res) => {
  res.send("API funcionando");
});

app.post("/api/login", async (req, res) => {
  const { correo, password } = req.body;

  try {
    const pool = await getPool();

    const result = await pool.request()
      .input("correo", sql.VarChar, correo)
      .query(`
        SELECT u.*, r.Nombre_Rol
        FROM dbo.Users u
        JOIN dbo.Roles r ON u.Id_Rol = r.Id_Rol
        WHERE u.Correo_Institucional = @correo
      `);

    if (result.recordset.length === 0) {
      return res.json({
        success: false,
        message: "Usuario no encontrado"
      });
    }

    const user = result.recordset[0];

    if (!user.Estado) {
      return res.json({
        success: false,
        message: "Cuenta desactivada. Contacte al administrador."
      });
    }

    const match = await bcrypt.compare(password, user.Password);

    if (!match) {
      return res.json({
        success: false,
        message: "Credenciales incorrectas"
      });
    }

    const token = jwt.sign(
      { id: user.Id, correo: user.Correo_Institucional },
      process.env.JWT_SECRET || "CLAVE_SUPER_SECRETA",
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.Id,
        nombre: user.Nombre,
        apellido: user.Apellido,
        correo: user.Correo_Institucional,
        rol: user.Nombre_Rol
      }
    });

  } catch (error) {
    console.log("LOGIN ERROR:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.post("/api/register", async (req, res) => {
  const { nombre, apellido, correo, password } = req.body;

  try {
    const pool = await getPool();

    const existingUser = await pool.request()
      .input("correo", sql.VarChar, correo)
      .query(`
        SELECT * FROM dbo.Users
        WHERE Correo_Institucional = @correo
      `);

    if (existingUser.recordset.length > 0) {
      return res.json({
        success: false,
        message: "El correo ya está registrado"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.request()
      .input("nombre", sql.VarChar, nombre)
      .input("apellido", sql.VarChar, apellido)
      .input("correo", sql.VarChar, correo)
      .input("password", sql.VarChar, hashedPassword)
      .query(`
        INSERT INTO dbo.Users
        (Nombre, Apellido, Correo_Institucional, Password, Estado, Id_Rol)
        VALUES (@nombre, @apellido, @correo, @password, 1, 2)
      `);

    res.json({
      success: true,
      message: "Usuario registrado correctamente"
    });

  } catch (error) {
    console.log("REGISTER ERROR:", error);
    res.status(500).json({ error: "Error al registrar usuario" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const { correo } = req.body;

  try {
    const pool = await getPool();

    const result = await pool.request()
      .input("correo", sql.VarChar, correo)
      .query(`
        SELECT * FROM dbo.Users
        WHERE Correo_Institucional = @correo
      `);

    if (result.recordset.length === 0) {
      return res.json({
        success: false,
        message: "Correo no encontrado"
      });
    }

    const token = crypto.randomBytes(20).toString("hex");

    await pool.request()
      .input("token", sql.VarChar, token)
      .input("correo", sql.VarChar, correo)
      .query(`
        UPDATE dbo.Users
        SET 
          ResetToken = @token,
          ResetTokenExpiration = DATEADD(MINUTE, 15, GETDATE())
        WHERE Correo_Institucional = @correo
      `);

    console.log("TOKEN:", token);

    res.json({
      success: true,
      message: "Token generado",
      token
    });

  } catch (error) {
    console.log("FORGOT ERROR:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;

  try {
    const pool = await getPool();

    const result = await pool.request()
      .input("token", sql.VarChar, token)
      .query(`
        SELECT * FROM dbo.Users
        WHERE ResetToken = @token
        AND ResetTokenExpiration > GETDATE()
      `);

    if (result.recordset.length === 0) {
      return res.json({
        success: false,
        message: "Token inválido o expirado"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.request()
      .input("password", sql.VarChar, hashedPassword)
      .input("token", sql.VarChar, token)
      .query(`
        UPDATE dbo.Users
        SET 
          Password = @password,
          ResetToken = NULL,
          ResetTokenExpiration = NULL
        WHERE ResetToken = @token
      `);

    res.json({
      success: true,
      message: "Contraseña actualizada"
    });

  } catch (error) {
    console.log("RESET ERROR:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.put("/api/update-user", async (req, res) => {
  const { id, nombre, apellido, password } = req.body;

  try {
    const pool = await getPool();

    if (password && password !== "") {
      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.request()
        .input("id", sql.Int, id)
        .input("nombre", sql.VarChar, nombre)
        .input("apellido", sql.VarChar, apellido)
        .input("password", sql.VarChar, hashedPassword)
        .query(`
          UPDATE dbo.Users
          SET 
            Nombre = @nombre,
            Apellido = @apellido,
            Password = @password
          WHERE Id = @id
        `);

    } else {
      await pool.request()
        .input("id", sql.Int, id)
        .input("nombre", sql.VarChar, nombre)
        .input("apellido", sql.VarChar, apellido)
        .query(`
          UPDATE dbo.Users
          SET 
            Nombre = @nombre,
            Apellido = @apellido
          WHERE Id = @id
        `);
    }

    res.json({ success: true });

  } catch (error) {
    console.log("UPDATE USER ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Error actualizando perfil"
    });
  }
});

app.get('/admin/resumen', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT 
        (SELECT COUNT(*) FROM dbo.Users) AS usuarios,
        (SELECT COUNT(*) FROM dbo.Units WHERE Estado = 1) AS unidades_activas,
        (SELECT COUNT(*) FROM dbo.Rutas WHERE Estado = 1) AS rutas_activas
    `);

    res.json(result.recordset[0]);

  } catch (error) {
    console.log("RESUMEN ERROR:", error);
    res.status(500).json({ error: "Error en servidor" });
  }
});

app.get('/admin/usuarios', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT 
        Id AS id,
        Nombre AS nombre,
        Apellido AS apellido,
        Correo_Institucional AS correo_institucional,
        Estado AS estado,
        Id_Rol AS id_rol
      FROM dbo.Users
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("USUARIOS ERROR:", error);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

app.put("/admin/usuarios/:id", async (req, res) => {
  try {
    const pool = await getPool();

    const { estado, id_rol } = req.body;
    const id = parseInt(req.params.id);

    await pool.request()
      .input("id", sql.Int, id)
      .input("estado", sql.Int, estado)
      .input("id_rol", sql.Int, id_rol)
      .query(`
        UPDATE dbo.Users
        SET 
          Estado = @estado,
          Id_Rol = @id_rol
        WHERE Id = @id
      `);

    res.json({
      success: true,
      message: "Usuario actualizado"
    });

  } catch (error) {
    console.log("UPDATE USER ADMIN ERROR:", error);
    res.status(500).json({ error: "Error actualizando usuario" });
  }
});

app.get('/admin/unidades', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT 
        Id_Unidad,
        Numero_Unidad,
        Estado,
        Placa,
        Capacidad_Asientos,
        Id_Chofer
      FROM dbo.Units
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("UNIDADES ERROR:", error);
    res.status(500).json({ error: "Error al obtener unidades" });
  }
});

app.post('/admin/unidades', async (req, res) => {
  try {
    const pool = await getPool();
    const { numero_unidad, placa, capacidad_asientos, id_chofer } = req.body;

    const result = await pool.request()
      .input("numeroUnidad", sql.Int, numero_unidad)
      .input("placa", sql.VarChar, placa)
      .input("capacidad", sql.Int, capacidad_asientos)
      .input("id_chofer", sql.Int, id_chofer)
      .query(`
        INSERT INTO Units (
          Numero_Unidad,
          Placa,
          Capacidad_Asientos,
          Id_Chofer
        )
        OUTPUT INSERTED.Id_Unidad
        VALUES (
          @numeroUnidad,
          @placa,
          @capacidad,
          @id_chofer
        )
      `);

    const unidadId = result.recordset[0].Id_Unidad;

    // ⚠️ IMPORTANTE: usar pool en loop
    for (let i = 1; i <= capacidad_asientos; i++) {
      await pool.request()
        .input("numero", sql.Int, i)
        .input("unidadId", sql.Int, unidadId)
        .query(`
          INSERT INTO Asientos (Numero_Asiento, Id_Unidad)
          VALUES (@numero, @unidadId)
        `);
    }

    res.json({ success: true, message: "Unidad creada con asientos" });

  } catch (error) {
    console.log("CREATE UNIDAD ERROR:", error);
    res.status(500).json({ error: "Error al crear unidad" });
  }
});

app.put('/admin/unidades/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const id = parseInt(req.params.id);
    const { numero_unidad, placa, capacidad_asientos, estado, id_chofer } = req.body;

    // Validar chofer
    if (id_chofer) {
      const existe = await pool.request()
        .input("id_chofer", sql.Int, id_chofer)
        .input("id_unidad", sql.Int, id)
        .query(`
          SELECT Id_Unidad 
          FROM Units 
          WHERE Id_Chofer = @id_chofer
          AND Id_Unidad != @id_unidad
        `);

      if (existe.recordset.length > 0) {
        return res.status(400).json({
          error: "Este chofer ya está asignado a otra unidad"
        });
      }
    }

    await pool.request()
      .input("id", sql.Int, id)
      .input("numero_unidad", sql.Int, numero_unidad ?? null)
      .input("placa", sql.VarChar, placa ?? null)
      .input("capacidad_asientos", sql.Int, capacidad_asientos ?? null)
      .input("estado", sql.Int, estado ?? null)
      .input("id_chofer", sql.Int, id_chofer ?? null)
      .query(`
        UPDATE dbo.Units
        SET
          Numero_Unidad = COALESCE(@numero_unidad, Numero_Unidad),
          Placa = COALESCE(@placa, Placa),
          Capacidad_Asientos = COALESCE(@capacidad_asientos, Capacidad_Asientos),
          Estado = COALESCE(@estado, Estado),
          Id_Chofer = COALESCE(@id_chofer, Id_Chofer)
        WHERE Id_Unidad = @id
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("UPDATE UNIDAD ERROR:", error);
    res.status(500).json({ error: "Error al actualizar unidad" });
  }
});

app.get('/admin/rutas', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT 
        r.Id_Ruta,
        r.Nombre_Ruta,
        r.Descripcion,
        r.Origen_Nombre,
        r.Destino_Nombre,
        r.Lat_Origen,
        r.Lng_Origen,
        r.Lat_Destino,
        r.Lng_Destino,
        r.Unidad_Id,
        u.Numero_Unidad,
        r.Estado,
        r.Fecha_Creacion
      FROM dbo.Rutas r
      LEFT JOIN dbo.Units u
        ON r.Unidad_Id = u.Id_Unidad
      ORDER BY r.Id_Ruta DESC
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("RUTAS ERROR:", error);
    res.status(500).json({ error: "Error al obtener rutas" });
  }
});

app.get('/admin/unidades-disponibles', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT 
        Id_Unidad,
        Numero_Unidad
      FROM dbo.Units
      WHERE Estado = 1
        AND Id_Unidad NOT IN (
          SELECT Unidad_Id
          FROM dbo.Rutas
          WHERE Estado = 1
        )
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("UNIDADES DISP ERROR:", error);
    res.status(500).json({ error: "Error al obtener unidades disponibles" });
  }
});

app.put('/admin/rutas/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const id = parseInt(req.params.id);
    const {
      Nombre_Ruta,
      Descripcion,
      Origen_Nombre,
      Destino_Nombre,
      Estado
    } = req.body;

    await pool.request()
      .input("id", sql.Int, id)
      .input("Nombre_Ruta", sql.VarChar, Nombre_Ruta)
      .input("Descripcion", sql.VarChar, Descripcion)
      .input("Origen_Nombre", sql.VarChar, Origen_Nombre)
      .input("Destino_Nombre", sql.VarChar, Destino_Nombre)
      .input("Estado", sql.Int, Estado ? 1 : 0)
      .query(`
        UPDATE dbo.Rutas
        SET
          Nombre_Ruta = @Nombre_Ruta,
          Descripcion = @Descripcion,
          Origen_Nombre = @Origen_Nombre,
          Destino_Nombre = @Destino_Nombre,
          Estado = @Estado
        WHERE Id_Ruta = @id
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("UPDATE RUTA ERROR:", error);
    res.status(500).json({ error: "Error al actualizar ruta" });
  }
});

app.post('/admin/rutas', async (req, res) => {
  try {
    const pool = await getPool();

    const {
      nombre_ruta,
      descripcion,
      origen_nombre,
      destino_nombre,
      lat_origen,
      lng_origen,
      lat_destino,
      lng_destino,
      unidad_id
    } = req.body;

    await pool.request()
      .input("nombre_ruta", sql.VarChar, nombre_ruta)
      .input("descripcion", sql.VarChar, descripcion)
      .input("origen_nombre", sql.VarChar, origen_nombre)
      .input("destino_nombre", sql.VarChar, destino_nombre)
      .input("lat_origen", sql.Float, lat_origen)
      .input("lng_origen", sql.Float, lng_origen)
      .input("lat_destino", sql.Float, lat_destino)
      .input("lng_destino", sql.Float, lng_destino)
      .input("unidad_id", sql.Int, unidad_id)
      .query(`
        INSERT INTO dbo.Rutas (
          Nombre_Ruta,
          Descripcion,
          Origen_Nombre,
          Destino_Nombre,
          Lat_Origen,
          Lng_Origen,
          Lat_Destino,
          Lng_Destino,
          Unidad_Id,
          Estado,
          Fecha_Creacion
        )
        VALUES (
          @nombre_ruta,
          @descripcion,
          @origen_nombre,
          @destino_nombre,
          @lat_origen,
          @lng_origen,
          @lat_destino,
          @lng_destino,
          @unidad_id,
          1,
          GETDATE()
        )
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("CREATE RUTA ERROR:", error);
    res.status(500).json({ error: "Error al crear ruta" });
  }
});

app.put('/admin/rutas/estado/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const id = parseInt(req.params.id);
    const { estado } = req.body;

    await pool.request()
      .input("id", sql.Int, id)
      .input("estado", sql.Int, estado)
      .query(`
        UPDATE dbo.Rutas
        SET Estado = @estado
        WHERE Id_Ruta = @id
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("ESTADO RUTA ERROR:", error);
    res.status(500).json({ error: "Error al actualizar estado" });
  }
});

app.delete('/admin/rutas/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const id = parseInt(req.params.id);

    await pool.request()
      .input("id", sql.Int, id)
      .query(`
        DELETE FROM dbo.Rutas
        WHERE Id_Ruta = @id
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("DELETE RUTA ERROR:", error);
    res.status(500).json({ error: "Error al eliminar ruta" });
  }
});

app.get('/usuario/rutas-activas', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT
        r.Id_Ruta,
        r.Nombre_Ruta,
        r.Origen_Nombre,
        r.Destino_Nombre,
        u.Numero_Unidad
      FROM dbo.Rutas r
      LEFT JOIN dbo.Units u
        ON r.Unidad_Id = u.Id_Unidad
      WHERE r.Estado = 1
      ORDER BY r.Nombre_Ruta
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("RUTAS ACTIVAS ERROR:", error);
    res.status(500).json({ error: "Error al obtener rutas activas" });
  }
});

app.get('/usuario/asientos/:rutaId', async (req, res) => {
  try {
    const pool = await getPool();

    const rutaId = parseInt(req.params.rutaId);

    const unidadResult = await pool.request()
      .input("RutaId", sql.Int, rutaId)
      .query(`
        SELECT Unidad_Id
        FROM Rutas
        WHERE Id_Ruta = @RutaId
      `);

    if (unidadResult.recordset.length === 0) {
      return res.status(404).json({ error: "Ruta no encontrada" });
    }

    const unidadId = unidadResult.recordset[0].Unidad_Id;

    const asientosResult = await pool.request()
      .input("UnidadId", sql.Int, unidadId)
      .query(`
        SELECT 
          Id_Asiento,
          Numero_Asiento,
          CAST(Estado AS INT) AS Estado
        FROM Asientos
        WHERE Id_Unidad = @UnidadId
        ORDER BY Numero_Asiento
      `);

    res.json(asientosResult.recordset);

  } catch (error) {
    console.log("ASIENTOS ERROR:", error);
    res.status(500).json({ error: "Error al obtener asientos" });
  }
});

app.put('/usuario/reservar-asiento/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const idAsiento = parseInt(req.params.id);
    const { rutaId } = req.body;

    const result = await pool.request()
      .input("Id", sql.Int, idAsiento)
      .input("RutaId", sql.Int, rutaId)
      .query(`
        UPDATE a
        SET 
          a.Estado = 1,
          a.Fecha_Reserva = GETDATE()
        FROM Asientos a
        INNER JOIN Rutas r
          ON a.Id_Unidad = r.Unidad_Id
        WHERE a.Id_Asiento = @Id
        AND r.Id_Ruta = @RutaId
        AND a.Estado = 0
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(400).json({ error: "No se pudo reservar el asiento" });
    }

    res.json({ success: true });

  } catch (error) {
    console.log("RESERVAR ERROR:", error);
    res.status(500).json({ error: "Error al reservar asiento" });
  }
});

app.put('/usuario/cancelar-reserva/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const idAsiento = parseInt(req.params.id);

    await pool.request()
      .input("Id", sql.Int, idAsiento)
      .query(`
        UPDATE Asientos
        SET 
          Estado = 0,
          Fecha_Reserva = NULL
        WHERE Id_Asiento = @Id
        AND Estado = 1
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("CANCELAR ERROR:", error);
    res.status(500).json({ error: "Error al cancelar reserva" });
  }
});

app.put('/usuario/ocupar-asiento/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const idAsiento = parseInt(req.params.id);
    const { rutaId } = req.body;

    const result = await pool.request()
      .input("Id", sql.Int, idAsiento)
      .input("RutaId", sql.Int, rutaId)
      .query(`
        UPDATE a
        SET 
          a.Estado = 2,
          a.Fecha_Reserva = NULL
        FROM Asientos a
        INNER JOIN Rutas r
          ON a.Id_Unidad = r.Unidad_Id
        WHERE a.Id_Asiento = @Id
        AND r.Id_Ruta = @RutaId
        AND a.Estado = 1
      `);

    if (result.rowsAffected[0] === 0) {
      return res.status(400).json({
        error: "No se pudo ocupar el asiento"
      });
    }

    res.json({ success: true });;

  } catch (error) {
    console.log("OCUPAR ERROR:", error);
    res.status(500).json({ error: "Error al ocupar asiento" });
  }
});

app.get('/usuario/estado-asiento/:id', async (req, res) => {
  try {
    const pool = await getPool();

    const idAsiento = parseInt(req.params.id);

    const result = await pool.request()
      .input("Id", sql.Int, idAsiento)
      .query(`
        SELECT Estado
        FROM Asientos
        WHERE Id_Asiento = @Id
      `);

    res.json(result.recordset[0]);

  } catch (error) {
    console.log("ESTADO ASIENTO ERROR:", error);
    res.status(500).json({ error: "Error" });
  }
});

app.put('/chofer/asientos/liberar-asientos', async (req, res) => {
  try {
    console.log("🔥 ENTRE A LIBERAR ASIENTOS");
    console.log("BODY:", req.body);
    const pool = await getPool();

    const { id_unidad, id_chofer } = req.body;

    console.log("Unidad:", id_unidad);
    console.log("Chofer:", id_chofer);

    const validacion = await pool.request()
      .input("id_unidad", sql.Int, id_unidad)
      .input("id_chofer", sql.Int, id_chofer)
      .query(`
        SELECT Id_Unidad
        FROM Units
        WHERE Id_Unidad = @id_unidad
        AND Id_Chofer = @id_chofer
      `);

    if (validacion.recordset.length === 0) {
      return res.status(403).json({
        success: false,
        message: "Esta unidad no pertenece al chofer"
      });
    }

    const result = await pool.request()
      .input("id_unidad", sql.Int, id_unidad)
      .query(`
        UPDATE Asientos
        SET 
          Estado = 0,
          Fecha_Reserva = NULL
        WHERE Id_Unidad = @id_unidad
        AND Estado IN (1, 2)
      `);

    console.log("FILAS AFECTADAS:", result.rowsAffected);

    if (result.rowsAffected[0] === 0) {
      return res.json({
        success: false,
        message: "No se actualizó ningún asiento"
      });
    }

    res.json({
      success: true,
      message: "Asientos liberados correctamente"
    });

  } catch (error) {
    console.log("ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Error en servidor"
    });
  }
});

app.put("/chofer/asientos/:id", async (req, res) => {
  try {
  
    const pool = await getPool();

    const { estado, id_chofer, id_unidad } = req.body;
    const id_asiento = parseInt(req.params.id);

    console.log("ID ASIENTO:", id_asiento);
    console.log("ID CHOFER:", id_chofer);
    console.log("ID UNIDAD:", id_unidad);

    const validacion = await pool.request()
      .input("id_chofer", sql.Int, id_chofer)
      .input("id_unidad", sql.Int, id_unidad)
      .input("id_asiento", sql.Int, id_asiento)
      .query(`
        SELECT a.Id_Asiento
        FROM Asientos a
        INNER JOIN Units u 
          ON a.Id_Unidad = u.Id_Unidad
        WHERE u.Id_Chofer = @id_chofer
          AND u.Id_Unidad = @id_unidad
          AND a.Id_Asiento = @id_asiento
      `);

    if (validacion.recordset.length === 0) {
      return res.status(403).json({
        success: false,
        message: "Este asiento no pertenece a tu unidad"
      });
    }

    await pool.request()
      .input("estado", sql.Int, estado)
      .input("id_asiento", sql.Int, id_asiento)
      .query(`
        UPDATE Asientos
        SET Estado = @estado
        WHERE Id_Asiento = @id_asiento
      `);

    res.json({ success: true });

  } catch (error) {
    console.log("CHOFER ASIENTO ERROR:", error);
    res.status(500).json({ error: "Error en servidor" });
  }
});

app.get('/admin/choferes', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request().query(`
      SELECT Id, Nombre, Apellido
      FROM dbo.Users
      WHERE Id_Rol = 3
    `);

    res.json(result.recordset);

  } catch (error) {
    console.log("CHOFERES ERROR:", error);
    res.status(500).json({ error: "Error al obtener choferes" });
  }
});

app.get('/chofer/unidad/:idChofer', async (req, res) => {
  try {
    const pool = await getPool();

    const idChofer = parseInt(req.params.idChofer);

    const result = await pool.request()
      .input('idChofer', sql.Int, idChofer)
      .query(`
        SELECT Id_Unidad
        FROM Units
        WHERE Id_Chofer = @idChofer
      `);

    if (result.recordset.length > 0) {
      return res.json({
        success: true,
        Id_Unidad: result.recordset[0].Id_Unidad
      });
    }

    res.json({
      success: false,
      message: "Chofer sin unidad asignada"
    });

  } catch (error) {
    console.log("UNIDAD CHOFER ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Error en servidor"
    });
  }
});

app.post("/chofer/ubicacion", async (req, res) => {
  try {
    const pool = await getPool();

    const { id_chofer, lat, lng } = req.body;

    await pool.request()
      .input("id_chofer", sql.Int, id_chofer)
      .input("lat", sql.Float, lat)
      .input("lng", sql.Float, lng)
      .query(`
        UPDATE Units
        SET Latitud = @lat,
            Longitud = @lng
        WHERE Id_Chofer = @id_chofer
      `);

    res.json({ success: true });

  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error actualizando ubicación" });
  }
});

app.get("/usuario/ubicacion-unidad/:rutaId", async (req, res) => {
  try {
    const pool = await getPool();
    const { rutaId } = req.params;

    const result = await pool.request()
      .input("rutaId", sql.Int, rutaId)
      .query(`
        SELECT u.Latitud, u.Longitud
        FROM Rutas r
        INNER JOIN Units u
          ON r.Unidad_Id = u.Id_Unidad
        WHERE r.Id_Ruta = @rutaId
      `);

    res.json(result.recordset[0]);

  } catch (error) {
    res.status(500).json({ error: "Error obteniendo ubicación" });
  }
});

app.get('/usuario/rutas', async (req, res) => {
  try {
    const pool = await getPool();
    const { busqueda } = req.query;

    const result = await pool.request()
      .input("busqueda", sql.VarChar, `%${busqueda}%`)
      .query(`
        SELECT
          Id_Ruta,
          Origen_Nombre,
          Destino_Nombre
        FROM Rutas
        WHERE Estado = 1
        AND (
          Origen_Nombre LIKE @busqueda
          OR Destino_Nombre LIKE @busqueda
        )
      `);

    res.json(result.recordset);

  } catch (error) {
    console.log("BUSCAR RUTAS ERROR:", error);
    res.status(500).json({ error: "Error en servidor" });
  }
});

app.put('/usuario/liberar-expirados', async (req, res) => {
  try {
    const pool = await getPool();

    await pool.request().query(`
      UPDATE Asientos
      SET Estado = 0,
          Fecha_Reserva = NULL
      WHERE Estado = 1
      AND DATEDIFF(MINUTE, Fecha_Reserva, GETDATE()) >= 5
    `);

    res.json({ success: true });

  } catch (error) {
    res.status(500).json({ error: "Error liberando asientos" });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});