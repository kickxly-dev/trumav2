/**
 * TRAUMA Discord Bot
 * License verification and management via Discord
 */

require('dotenv').config();
const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, PermissionsBitField } = require('discord.js');
const axios = require('axios');

// Config
const DISCORD_TOKEN = process.env.DISCORD_BOT_TOKEN;
const LICENSE_SERVER = process.env.LICENSE_SERVER || 'http://localhost:3001';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const WELCOME_CHANNEL_ID = process.env.WELCOME_CHANNEL_ID;
const LICENSED_ROLE_ID = process.env.LICENSED_ROLE_ID;

// Create client with all needed intents
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessageReactions
    ]
});

// Store verified users in memory (use database in production)
const verifiedUsers = new Map();

// Slash commands
const commands = [
    new SlashCommandBuilder()
        .setName('verify')
        .setDescription('Verify your TRAUMA license')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('Your TRAUMA license key')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('activate')
        .setDescription('Activate a license (Admin only)')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('License key to activate')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('status')
        .setDescription('Check your license status'),
    
    new SlashCommandBuilder()
        .setName('generate')
        .setDescription('Generate a new license (Admin only)')
        .addStringOption(option =>
            option.setName('user')
                .setDescription('Username for the license')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('License duration in days')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('revoke')
        .setDescription('Revoke a license (Admin only)')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('License key to revoke')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('list')
        .setDescription('List all licenses (Admin only)')
        .addIntegerOption(option =>
            option.setName('limit')
                .setDescription('Number of licenses to show')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('stats')
        .setDescription('Show license server statistics (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('referral')
        .setDescription('Create a referral code (Admin only)')
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Referral name')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('bonus')
                .setDescription('Bonus days for referral')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('extend')
        .setDescription('Extend your license with a referral code')
        .addStringOption(option =>
            option.setName('code')
                .setDescription('Referral code')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('key')
                .setDescription('Your license key')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('help')
        .setDescription('Show TRAUMA bot help')
];

// Register commands
async function registerCommands() {
    const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
    
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(client.user.id),
            { body: commands }
        );
        console.log('Commands registered!');
    } catch (error) {
        console.error('Error registering commands:', error);
    }
}

// Check if user is admin
function isAdmin(userId) {
    const adminIds = process.env.ADMIN_IDS?.split(',') || [];
    return adminIds.includes(userId);
}

// API helper
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const config = {
            method,
            url: `${LICENSE_SERVER}${endpoint}`,
            headers: {
                'x-api-key': ADMIN_API_KEY,
                'Content-Type': 'application/json'
            }
        };
        if (data) config.data = data;
        const response = await axios(config);
        return response.data;
    } catch (error) {
        return { error: error.response?.data?.error || error.message };
    }
}

// Events
client.once('ready', () => {
    console.log(`✅ TRAUMA Discord Bot logged in as ${client.user.tag}`);
    registerCommands();
});

// Welcome new members
client.on('guildMemberAdd', async (member) => {
    try {
        const channel = member.guild.channels.cache.get(WELCOME_CHANNEL_ID);
        if (!channel) return;
        
        const embed = new EmbedBuilder()
            .setColor(0xdc143c)
            .setTitle('🎯 Welcome to TRAUMA')
            .setDescription(`Hey ${member}, welcome to the TRAUMA community!`)
            .addFields(
                { name: '🔐 Get Access', value: 'Use `/verify <your-license-key>` to unlock all features', inline: false },
                { name: '📦 Get a License', value: 'Contact an admin to purchase a license', inline: true },
                { name: '📚 Documentation', value: 'Check out our guides in the channels', inline: true }
            )
            .setThumbnail(member.user.displayAvatarURL())
            .setFooter({ text: 'TRAUMA Security Suite' })
            .setTimestamp();
        
        await channel.send({ content: `<@${member.id}>`, embeds: [embed] });
    } catch (e) {
        console.error('Welcome error:', e.message);
    }
});

// Assign role when user verifies license
async function assignLicensedRole(userId, guild) {
    if (!LICENSED_ROLE_ID || !guild) return;
    
    try {
        const member = await guild.members.fetch(userId);
        if (member && !member.roles.cache.has(LICENSED_ROLE_ID)) {
            await member.roles.add(LICENSED_ROLE_ID);
            console.log(`✅ Assigned licensed role to ${member.user.tag}`);
        }
    } catch (e) {
        console.error('Role assignment error:', e.message);
    }
}

// Remove role when license expires/revoked
async function removeLicensedRole(userId, guild) {
    if (!LICENSED_ROLE_ID || !guild) return;
    
    try {
        const member = await guild.members.fetch(userId);
        if (member && member.roles.cache.has(LICENSED_ROLE_ID)) {
            await member.roles.remove(LICENSED_ROLE_ID);
            console.log(`🔴 Removed licensed role from ${member.user.tag}`);
        }
    } catch (e) {
        console.error('Role removal error:', e.message);
    }
}

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    
    const { commandName, user, options } = interaction;
    
    switch (commandName) {
        case 'verify': {
            const key = options.getString('key');
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/license/validate', 'POST', { key });
            
            if (result.valid) {
                verifiedUsers.set(user.id, { key, user: result.user, expires: result.expires });
                
                // Assign licensed role
                await assignLicensedRole(user.id, interaction.guild);
                
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Verified')
                    .setDescription(`Welcome to TRAUMA, **${result.user}**!`)
                    .addFields(
                        { name: 'Days Remaining', value: `${result.daysRemaining} days`, inline: true },
                        { name: 'Expires', value: new Date(result.expires).toLocaleDateString(), inline: true },
                        { name: 'Role', value: 'Licensed role assigned! 🎉', inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('❌ License Invalid')
                    .setDescription(result.error || 'License verification failed')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
            }
            break;
        }
        
        case 'activate': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            const key = options.getString('key');
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/license/activate', 'POST', { key, hardwareId: user.id });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Activated')
                    .setDescription(`License activated for **${result.user}**`)
                    .addFields(
                        { name: 'Key', value: `\`${key}\``, inline: false },
                        { name: 'Days Remaining', value: `${result.daysRemaining} days`, inline: true },
                        { name: 'Expires', value: new Date(result.expires).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'Now shows as ACTIVE in license manager' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('❌ Activation Failed')
                    .setDescription(result.error || 'Activation failed')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
            }
            break;
        }
        
        case 'status': {
            await interaction.deferReply({ ephemeral: true });
            
            const verified = verifiedUsers.get(user.id);
            if (!verified) {
                const embed = new EmbedBuilder()
                    .setColor(0xffaa00)
                    .setTitle('⚠️ Not Verified')
                    .setDescription('Use `/verify` to verify your license first')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
                return;
            }
            
            const result = await apiCall('/api/license/validate', 'POST', { key: verified.key });
            
            const embed = new EmbedBuilder()
                .setColor(result.valid ? 0x00ff88 : 0xff4444)
                .setTitle(result.valid ? '✅ License Active' : '❌ License Invalid')
                .addFields(
                    { name: 'User', value: verified.user, inline: true },
                    { name: 'Days Remaining', value: result.daysRemaining ? `${result.daysRemaining} days` : 'N/A', inline: true },
                    { name: 'Expires', value: new Date(verified.expires).toLocaleDateString(), inline: true }
                )
                .setFooter({ text: 'TRAUMA License System' })
                .setTimestamp();
            
            await interaction.editReply({ embeds: [embed] });
            break;
        }
        
        case 'generate': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const username = options.getString('user');
            const days = options.getInteger('days') || 365;
            
            const result = await apiCall('/api/admin/license/generate', 'POST', { user: username, expiryDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🔑 License Generated')
                    .addFields(
                        { name: 'User', value: result.license.user, inline: true },
                        { name: 'Key', value: `\`${result.license.key}\``, inline: false },
                        { name: 'Expires', value: new Date(result.license.expiry).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'revoke': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const key = options.getString('key');
            const result = await apiCall('/api/admin/license/revoke', 'POST', { key });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('🚫 License Revoked')
                    .setDescription(`License \`${key}\` has been revoked`)
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'list': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses');
            const limit = options.getInteger('limit') || 10;
            
            if (result.licenses) {
                const licenses = result.licenses.slice(0, limit);
                
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle(`📋 Licenses (${result.licenses.length} total)`)
                    .setDescription(licenses.map((l, i) => 
                        `**${i + 1}.** ${l.user} - \`${l.key.substring(0, 15)}...\` ${l.revoked ? '❌' : '✅'}`
                    ).join('\n'))
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'stats': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/analytics');
            
            if (result.stats) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('📊 License Server Statistics')
                    .addFields(
                        { name: 'Total Events', value: `${result.stats.totalEvents}`, inline: true },
                        { name: 'Validations', value: `${result.stats.validations}`, inline: true },
                        { name: 'Activations', value: `${result.stats.activations}`, inline: true },
                        { name: 'Failed Validations', value: `${result.stats.failedValidations}`, inline: true },
                        { name: 'Licenses Generated', value: `${result.stats.licensesGenerated}`, inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'referral': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const name = options.getString('name');
            const bonus = options.getInteger('bonus') || 30;
            
            const result = await apiCall('/api/referral/create', 'POST', { name, bonusDays: bonus });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🎁 Referral Code Created')
                    .addFields(
                        { name: 'Code', value: `\`${result.referral.code}\``, inline: true },
                        { name: 'Bonus Days', value: `${bonus} days`, inline: true },
                        { name: 'Max Uses', value: `${result.referral.maxUses}`, inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'extend': {
            await interaction.deferReply({ ephemeral: true });
            
            const code = options.getString('code');
            const key = options.getString('key');
            
            const result = await apiCall('/api/referral/use', 'POST', { referralCode: code, key });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Extended')
                    .setDescription(result.message)
                    .addFields(
                        { name: 'New Expiry', value: new Date(result.newExpiry).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'help': {
            const embed = new EmbedBuilder()
                .setColor(0xdc143c)
                .setTitle('🛡️ TRAUMA Bot Help')
                .setDescription('License management commands for TRAUMA Suite')
                .addFields(
                    { name: '/verify <key>', value: 'Verify your TRAUMA license' },
                    { name: '/status', value: 'Check your license status' },
                    { name: '/extend <code> <key>', value: 'Extend license with referral code' },
                    { name: '/generate <user> [days]', value: 'Generate license (Admin)' },
                    { name: '/revoke <key>', value: 'Revoke license (Admin)' },
                    { name: '/list [limit]', value: 'List licenses (Admin)' },
                    { name: '/stats', value: 'Server statistics (Admin)' },
                    { name: '/referral <name> [bonus]', value: 'Create referral (Admin)' }
                )
                .setFooter({ text: 'One license works for all TRAUMA tools' })
                .setTimestamp();
            
            await interaction.reply({ embeds: [embed], ephemeral: true });
            break;
        }
    }
});

// Login
client.login(DISCORD_TOKEN);

module.exports = client;
